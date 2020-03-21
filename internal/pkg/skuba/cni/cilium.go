/*
 * Copyright (c) 2019 SUSE LLC.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package cni

import (
	"bufio"
	"bytes"
	"crypto/x509"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/pkg/errors"
	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
	certutil "k8s.io/client-go/util/cert"
	"k8s.io/client-go/util/keyutil"
	"k8s.io/client-go/util/retry"
	"k8s.io/klog"
	"k8s.io/kubectl/pkg/scheme"
	kubeadmconstants "k8s.io/kubernetes/cmd/kubeadm/app/constants"
	"k8s.io/kubernetes/cmd/kubeadm/app/util/apiclient"
	"k8s.io/kubernetes/cmd/kubeadm/app/util/pkiutil"
	"sigs.k8s.io/yaml"

	"github.com/SUSE/skuba/internal/pkg/skuba/kubeadm"
	"github.com/SUSE/skuba/internal/pkg/skuba/kubernetes"
	skubaconstants "github.com/SUSE/skuba/pkg/skuba"
)

const (
	ciliumSecretName      = "cilium-secret"
	ciliumConfigMapName   = "cilium-config"
	ciliumUpdateLabelsFmt = `{"spec":{"template":{"metadata":{"labels":{"caasp.suse.com/skuba-updated-at":"%v"}}}}}`
	etcdEndpointFmt       = "https://%s:2379"
	etcdCAFileName        = "/tmp/cilium-etcd/ca.crt"
	etcdCertFileName      = "/tmp/cilium-etcd/tls.crt"
	etcdKeyFileName       = "/tmp/cilium-etcd/tls.key"
)

var (
	ciliumCertConfig = certutil.Config{
		CommonName:   "cilium-etcd-client",
		Organization: []string{kubeadmconstants.SystemPrivilegedGroup},
		Usages:       []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	etcdDir        = filepath.Join("pki", "etcd")
	migrationRetry = wait.Backoff{
		Steps:    20,
		Duration: 5 * time.Second,
		Factor:   1.0,
		Jitter:   0.1,
	}
)

type EtcdConfig struct {
	Endpoints []string `json:"endpoints"`
	CAFile    string   `json:"ca-file"`
	CertFile  string   `json:"cert-file"`
	KeyFile   string   `json:"key-file"`
}

func CreateCiliumSecret(client clientset.Interface) error {
	caCert, caKey, err := pkiutil.TryLoadCertAndKeyFromDisk(etcdDir, "ca")
	if err != nil {
		return errors.Errorf("etcd generation retrieval failed %v", err)
	}
	cert, key, err := pkiutil.NewCertAndKey(caCert, caKey, &ciliumCertConfig)
	if err != nil {
		return errors.Errorf("error when creating etcd client certificate for cilium %v", err)
	}

	privateKey, err := keyutil.MarshalPrivateKeyToPEM(key)
	if err != nil {
		return errors.Errorf("etcd private key marshal failed %v", err)
	}

	secret := &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ciliumSecretName,
			Namespace: metav1.NamespaceSystem,
		},
		Data: map[string][]byte{
			v1.TLSCertKey:       pkiutil.EncodeCertPEM(cert),
			v1.TLSPrivateKeyKey: privateKey,
			"ca.crt":            pkiutil.EncodeCertPEM(caCert),
		},
	}

	if err = apiclient.CreateOrUpdateSecret(client, secret); err != nil {
		return errors.Errorf("error when creating cilium secret  %v", err)
	}
	return nil
}

func CiliumSecretExists(client clientset.Interface) (bool, error) {
	_, err := client.CoreV1().Secrets(metav1.NamespaceSystem).Get(ciliumSecretName, metav1.GetOptions{})
	return kubernetes.DoesResourceExistWithError(err)
}

// NeedsEtcdToCrdMigration checks if the migration from etcd to CRD is needed,
// which is the case when upgrading from Cilium 1.5 to Cilium 1.6. Decision
// depends on the old Cilium ConfigMap. If that config map exists and contains
// the etcd config, migration has to be done. If not, it means that we have a
// fresh deployment of Cilium 1.6 configured to use CRD and no migration is
// needed.
func NeedsEtcdToCrdMigration(client clientset.Interface) (bool, error) {
	configMap, err := client.CoreV1().ConfigMaps(
		metav1.NamespaceSystem).Get(
		ciliumConfigMapName, metav1.GetOptions{})
	if err != nil {
		// If the old config map is not found, etcd config and migration
		// to CRD are not needed.
		if apierrors.IsNotFound(err) {
			return false, nil
		}
		return false, errors.Wrap(err, "could not retrieve old cilium configmap, although it exists")
	}
	_, ok := configMap.Data["etcd-config"]
	return ok, nil
}

func CreateOrUpdateCiliumConfigMap(client clientset.Interface) error {
	ciliumConfigMapData := map[string]string{
		"bpf-ct-global-tcp-max":    "524288",
		"bpf-ct-global-any-max":    "262144",
		"debug":                    "false",
		"enable-ipv4":              "true",
		"enable-ipv6":              "false",
		"identity-allocation-mode": "crd",
		"preallocate-bpf-maps":     "false",
	}

	needsEtcdConfig, err := NeedsEtcdToCrdMigration(client)
	if err != nil {
		return err
	}
	if needsEtcdConfig {
		etcdEndpoints := []string{}
		apiEndpoints, err := kubeadm.GetAPIEndpointsFromConfigMap(client)
		if err != nil {
			return errors.Wrap(err, "unable to get api endpoints")
		}
		for _, endpoints := range apiEndpoints {
			etcdEndpoints = append(etcdEndpoints, fmt.Sprintf(etcdEndpointFmt, endpoints))
		}
		etcdConfigData := EtcdConfig{
			Endpoints: etcdEndpoints,
			CAFile:    etcdCAFileName,
			CertFile:  etcdCertFileName,
			KeyFile:   etcdKeyFileName,
		}

		etcdConfigDataByte, err := yaml.Marshal(&etcdConfigData)
		if err != nil {
			return err
		}

		ciliumConfigMapData["etcd-config"] = string(etcdConfigDataByte)
		ciliumConfigMapData["identity-allocation-mode"] = "kvstore"
	}

	ciliumConfigMap := &v1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ciliumConfigMapName,
			Namespace: metav1.NamespaceSystem,
		},
		Data: ciliumConfigMapData,
	}

	if err := apiclient.CreateOrUpdateConfigMap(client, ciliumConfigMap); err != nil {
		return errors.Wrap(err, "error when creating cilium config ")
	}

	return nil
}

// MigrateEtcdToCrd performs the migration of Cilium internal data from etcd
// cluster to CRD during upgrade from Cilium 1.5 to Cilium 1.6. This step is not
// mandatory, without it, Cilium is going to regenerate data from scratch which
// might result in service downtimes. If the automated migration is not
// successful, the upgrade will be continued without migration and user will be
// warned about downtime of services.
func MigrateEtcdToCrd(client clientset.Interface, config *rest.Config) error {
	var ciliumPod string

	klog.Info("starting migration from etcd to CRD as a data store for cilium")

	// Find any Cilium pod.
	if err := retry.OnError(migrationRetry, IsErrCiliumNotFound, func() error {
		pods, err := client.CoreV1().Pods(metav1.NamespaceSystem).List(metav1.ListOptions{
			LabelSelector: "k8s-app=cilium",
		})
		if err != nil {
			return errors.Wrap(err, "could not find cilium pods")
		}
		if len(pods.Items) < 1 {
			return ErrCiliumNotFound
		}
		ciliumPod = pods.Items[0].GetName()
		// Wait until the Cilium pod is not in the pending status and
		// check whether it's running.
		klog.Infof("waiting for availability of cilium pod %s", ciliumPod)
		var pod *v1.Pod
		for {
			var err error
			pod, err = client.CoreV1().Pods(metav1.NamespaceSystem).Get(ciliumPod, metav1.GetOptions{})
			if err != nil {
				return errors.Wrapf(ErrCiliumNotFound, "could not get cilium pod: %v", err)
			}
			if pod.Status.Phase != v1.PodPending {
				break
			}
		}
		if pod.Status.Phase != v1.PodRunning {
			return ErrCiliumPodUnsuccessful
		}
		if !strings.Contains(pod.Spec.Containers[0].Image, ":1.6") {
			return ErrCiliumNotFound
		}

		return nil
	}); err != nil {
		return err
	}

	// Perform the migration.
	req := client.CoreV1().RESTClient().Post().Resource("pods").Name(ciliumPod).
		Namespace(metav1.NamespaceSystem).SubResource("exec")
	option := &v1.PodExecOptions{
		Command: []string{"cilium", "preflight", "migrate-identity"},
		Stdin:   false,
		Stdout:  true,
		Stderr:  true,
		TTY:     true,
	}
	req.VersionedParams(
		option,
		scheme.ParameterCodec,
	)
	exec, err := remotecommand.NewSPDYExecutor(config, "POST", req.URL())
	if err != nil {
		return err
	}
	var stdout, stderr bytes.Buffer
	bStdout := bufio.NewWriter(&stdout)
	bStderr := bufio.NewWriter(&stderr)
	err = exec.Stream(remotecommand.StreamOptions{
		Stdout: bStdout,
		Stderr: bStderr,
	})
	bStdout.Flush()
	bStderr.Flush()
	if err != nil {
		return errors.Errorf("could not migrate data from etcd to CRD: %v; stdout: %v; stderr: %v",
			err, stdout.String(), stderr.String())
	}

	klog.Info("successfully migrated from etcd to CRD")

	return nil
}

func RemoveEtcdConfig(client clientset.Interface) error {
	cm, err := client.CoreV1().ConfigMaps(metav1.NamespaceSystem).Get(ciliumConfigMapName, metav1.GetOptions{})
	if err != nil {
		return errors.Wrap(err, "could not get cilium config map")
	}
	delete(cm.Data, "etcd-config")
	if _, err := client.CoreV1().ConfigMaps(metav1.NamespaceSystem).Update(cm); err != nil {
		return errors.Wrap(err, "could not update cilium config map")
	}
	return nil
}

func RestartCiliumDs() error {
	cmd := exec.Command("kubectl", "-n", "kube-system", "rollout", "--kubeconfig", skubaconstants.KubeConfigAdminFile(), "restart", "ds/cilium")
	if combinedOutput, err := cmd.CombinedOutput(); err != nil {
		klog.Errorf("failed to restart cilium daemonset: %s", combinedOutput)
		return err
	}
	return nil
}

func CiliumUpdateConfigMap(client clientset.Interface) error {
	if err := CreateOrUpdateCiliumConfigMap(client); err != nil {
		return err
	}
	return annotateCiliumDaemonsetWithCurrentTimestamp(client)
}

func annotateCiliumDaemonsetWithCurrentTimestamp(client clientset.Interface) error {
	patch := fmt.Sprintf(ciliumUpdateLabelsFmt, time.Now().Unix())
	_, err := client.AppsV1().DaemonSets(metav1.NamespaceSystem).Patch("cilium", types.StrategicMergePatchType, []byte(patch))
	if err != nil {
		return err
	}

	klog.V(1).Info("successfully annotated cilium daemonset with current timestamp, which will restart all cilium pods")
	return nil
}
