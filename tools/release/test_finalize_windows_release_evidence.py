import importlib.util, json, sys, unittest
from pathlib import Path
P=Path(__file__).with_name("finalize_windows_release_evidence.py"); S=importlib.util.spec_from_file_location("r",P); M=importlib.util.module_from_spec(S); sys.modules[S.name]=M; S.loader.exec_module(M)
C="1"*40; D="a"*64; V="b"*64; I="c"*64; CERT="d"*64

def policy():
    return {"schema_version":"0.1.0","policy_id":"ergaxiom.windows-production-release","canonical_installer":"nsis","signing":{"identity_status":"OWNER_APPROVED_PINNED","expected_subject":"CN=Owner","expected_certificate_sha256":CERT,"digest_algorithm":"SHA256","timestamp_protocol":"RFC3161","timestamp_url":"https://timestamp.digicert.com","require_online_revocation":True,"reject_self_signed":True},"packaging":{"targets":["nsis"],"install_mode":"perMachine","allow_downgrades":False,"service_name":"ErgaxiomProductionSigner","uninstall_preserves_production_state":True},"license":{"owner_decision_status":"APPROVED","spdx_expression":"Apache-2.0"},"shipping_inventory":{"signed_pe_artifacts":[{"artifact_id":"desktop","name":"ergaxiom-desktop.exe","build_input":"apps/desktop/src-tauri","disposition":"SHIPPED_EXECUTABLE"},{"artifact_id":"production_signer_service","name":"ergaxiom-windows-production-signer-service.exe","build_input":"apps/windows-production-signer-service","disposition":"SHIPPED_EXECUTABLE"}],"linked_runtime_inputs":[{"artifact_id":"windows_uia_client","build_input":"crates/windows-uia-client-runtime","disposition":"LINKED_INTO_DESKTOP"},{"artifact_id":"windows_bridge","build_input":"crates/windows-bridge-runtime","disposition":"LINKED_INTO_DESKTOP"},{"artifact_id":"inkscape_adapter","build_input":"crates/inkscape-adapter-runtime","disposition":"LINKED_RUNTIME"}],"installer":{"artifact_id":"windows_installer","format":"NSIS","filename_glob":"*-setup.exe","disposition":"SHIPPED_INSTALLER"}}}
def base():return {"product":"ergaxiom-desktop","source":{"commit":C},"artifacts":[{"name":"ergaxiom-desktop.exe","sha256":D},{"name":"ergaxiom-windows-production-signer-service.exe","sha256":V},{"name":"Ergaxiom_0.1.0_x64-setup.exe","sha256":I}],"release_eligible":False}
def sig(p):
    rs=[]
    for n,d in [("ergaxiom-desktop.exe",D),("ergaxiom-windows-production-signer-service.exe",V),("Ergaxiom_0.1.0_x64-setup.exe",I)]:rs.append({"name":n,"sha256":d,"authenticode_valid":True,"signtool_verify_ok":True,"certificate_chain_valid":True,"revocation_checked_online":True,"timestamp_present":True,"timestamp_chain_valid":True,"signer_subject":"CN=Owner","signer_certificate_sha256":CERT,"timestamp_url":p["signing"]["timestamp_url"],"self_signed":False})
    return {"schema_version":"0.1.0","mode":"production","test_identity":False,"policy_sha256":M.sha(p),"artifacts":rs}
def life(test=False):return {"schema_version":"0.1.0","source_commit":C,"installer_name":"Ergaxiom_0.1.0_x64-setup.exe","installer_sha256":I,"test_mode":test,"phases":{k:True for k in ["clean_install","upgrade","downgrade_rejected","interrupted_upgrade_preserved_state","recovery_install","uninstall","production_state_preserved"]}}
def gate(n):return {"schema_version":"0.1.0","gate":n,"source_commit":C,"verified":True,"evidence_artifacts":[{"name":n,"sha256":"e"*64}]}
def lic():return {"schema_version":"0.1.0","source_commit":C,"owner_approved":True,"spdx_expression":"Apache-2.0"}
class T(unittest.TestCase):
    def accepted(self,p=None,s=None,l=None):
        p=p or policy(); return M.build(base(),p,s or sig(p),l or life(),gate("production_chain"),gate("hardware_operational"),lic())
    def test_all_proven(self):self.assertTrue(self.accepted()["release_eligible"])
    def test_test_identity_rejected(self):
        p=policy(); s=sig(p); s["mode"]="test"; s["test_identity"]=True; self.assertFalse(self.accepted(p,s)["release_eligible"])
    def test_wrong_chain_timestamp_subject_rejected(self):
        for key,val in [("certificate_chain_valid",False),("timestamp_present",False),("signer_subject","CN=Wrong")]:
            p=policy(); s=sig(p); s["artifacts"][0][key]=val; self.assertFalse(self.accepted(p,s)["release_eligible"])
    def test_post_sign_mutation_rejected(self):
        p=policy(); s=sig(p); s["artifacts"][0]["sha256"]="f"*64
        with self.assertRaises(M.ReleaseError):self.accepted(p,s)
    def test_partial_inventory_rejected(self):
        b=base(); b["artifacts"].pop(1)
        with self.assertRaises(M.ReleaseError):M.build(b,policy())
    def test_test_lifecycle_rejected(self):self.assertFalse(self.accepted(l=life(True))["release_eligible"])
if __name__=="__main__":unittest.main()
