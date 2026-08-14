import importlib.util, sys, unittest
from pathlib import Path
P=Path(__file__).with_name("finalize_windows_release_evidence.py"); S=importlib.util.spec_from_file_location("r",P); M=importlib.util.module_from_spec(S); sys.modules[S.name]=M; S.loader.exec_module(M)
C="1"*40; D="a"*64; V="b"*64; I="c"*64; CERT="d"*64

def policy():
    return {"schema_version":"0.1.0","policy_id":"ergaxiom.windows-production-release","canonical_installer":"nsis","signing":{"identity_status":"OWNER_APPROVED_PINNED","expected_subject":"CN=Owner","expected_certificate_sha256":CERT,"certificate_store_location":"CurrentUser","certificate_store_name":"My","code_signing_eku_oid":"1.3.6.1.5.5.7.3.3","digest_algorithm":"SHA256","timestamp_digest_algorithm":"SHA256","timestamp_protocol":"RFC3161","timestamp_url":"https://timestamp.digicert.com","require_online_revocation":True,"reject_self_signed":True},"packaging":{"targets":["nsis"],"install_mode":"perMachine","install_root":"%ProgramFiles%\\Ergaxiom","production_state_root":"%ProgramData%\\Ergaxiom","allow_downgrades":False,"service_name":"ErgaxiomProductionSigner","uninstall_preserves_production_state":True},"license":{"owner_decision_status":"APPROVED","spdx_expression":"Apache-2.0"},"shipping_inventory":{"signed_pe_artifacts":[{"artifact_id":"desktop","name":"ergaxiom-desktop.exe","build_input":"apps/desktop/src-tauri","disposition":"SHIPPED_EXECUTABLE"},{"artifact_id":"production_signer_service","name":"ergaxiom-windows-production-signer-service.exe","build_input":"apps/windows-production-signer-service","disposition":"SHIPPED_EXECUTABLE"}],"linked_runtime_inputs":[{"artifact_id":"windows_uia_client","build_input":"crates/windows-uia-client-runtime","disposition":"LINKED_INTO_DESKTOP"},{"artifact_id":"windows_bridge","build_input":"crates/windows-bridge-runtime","disposition":"LINKED_INTO_DESKTOP"},{"artifact_id":"inkscape_adapter","build_input":"crates/inkscape-adapter-runtime","disposition":"LINKED_RUNTIME"}],"installer":{"artifact_id":"windows_installer","format":"NSIS","filename_glob":"*-setup.exe","disposition":"SHIPPED_INSTALLER"}}}
def base(): return {"product":"ergaxiom-desktop","source":{"commit":C},"artifacts":[{"name":"ergaxiom-desktop.exe","sha256":D},{"name":"ergaxiom-windows-production-signer-service.exe","sha256":V},{"name":"Ergaxiom_0.1.0_x64-setup.exe","sha256":I}],"release_eligible":False}
def sig(p):
    rs=[]
    for n,d in [("ergaxiom-desktop.exe",D),("ergaxiom-windows-production-signer-service.exe",V),("Ergaxiom_0.1.0_x64-setup.exe",I)]:
        rs.append({"name":n,"sha256":d,"authenticode_valid":True,"signtool_verify_ok":True,"code_signing_eku_present":True,"certificate_chain_valid":True,"revocation_checked_online":True,"timestamp_present":True,"timestamp_chain_valid":True,"signer_subject":"CN=Owner","signer_certificate_sha256":CERT,"timestamp_url":p["signing"]["timestamp_url"],"self_signed":False})
    return {"schema_version":"0.1.0","mode":"production","test_identity":False,"signtool_available":True,"policy_sha256":M.sha(p),"artifacts":rs}
def life(test=False):
    phases=["clean_install","service_installed_local_system","service_validated_running","protected_state_acl_verified","upgrade","downgrade_rejected","interrupted_upgrade_preserved_state","rollback_recovery","recovery_install","uninstall","production_state_preserved"]
    return {"schema_version":"0.1.0","source_commit":C,"installer_name":"Ergaxiom_0.1.0_x64-setup.exe","installer_sha256":I,"test_mode":test,"phases":{k:True for k in phases}}
def gate(n): return {"schema_version":"0.1.0","gate":n,"source_commit":C,"verified":True,"evidence_artifacts":[{"name":n,"sha256":"e"*64}]}
def lic(): return {"schema_version":"0.1.0","source_commit":C,"owner_approved":True,"spdx_expression":"Apache-2.0"}
def canonical_prod():
    value={"schema_version":"0.1.0","verifier_id":M.PRODUCTION_VERIFIER_ID,"gate":M.PRODUCTION_GATE,"verified":True,"source_commit":C,"job_id":"job.release.1","chain_stage":"certified","chain_revision":7,"chain_state_digest":"e"*64,"signer_service_sha256":V,"trust_state_binding_digest":"f"*64,"signer_identity_proof_digest":"1"*64,"certificate_id":"cert.release.1","certificate_digest":"2"*64,"replay_manifest_digest":"3"*64,"evidence_bundle_digest":"4"*64,"decision":"ACCEPTED","assurance_level":"E5","input_digests":{k:chr(97+i)*64 for i,k in enumerate(sorted(M.PRODUCTION_INPUTS))},"verification_digest":""}
    value["verification_digest"]=M.sha(value)
    return value

class T(unittest.TestCase):
    def accepted(self,p=None,s=None,l=None,prod=None,hw=None):
        p=p or policy(); return M.build(base(),p,s or sig(p),l or life(),prod if prod is not None else gate("production_chain"),hw if hw is not None else gate("hardware_operational"),lic())
    def test_summary_only_external_evidence_never_promotes(self):
        r=self.accepted(); self.assertFalse(r["release_eligible"]); self.assertFalse(r["production_chain"]["verified"]); self.assertFalse(r["hardware_operational"]["verified"]); self.assertIn("PRODUCTION_CHAIN_EVIDENCE_NOT_VERIFIED",r["blocking_reasons"]); self.assertNotIn("PRODUCTION_CHAIN_CANONICAL_VERIFIER_NOT_INTEGRATED",r["blocking_reasons"])
    def test_canonical_production_verifier_evidence_is_accepted(self):
        r=self.accepted(prod=canonical_prod()); self.assertTrue(r["production_chain"]["verified"]); self.assertNotIn("PRODUCTION_CHAIN_EVIDENCE_NOT_VERIFIED",r["blocking_reasons"])
    def test_canonical_production_service_substitution_is_rejected(self):
        p=canonical_prod(); p["signer_service_sha256"]="9"*64; p["verification_digest"]=""; p["verification_digest"]=M.sha(p); self.assertFalse(self.accepted(prod=p)["production_chain"]["verified"])
    def test_rolled_back_chain_is_not_release_eligible(self):
        p=canonical_prod(); p["chain_stage"]="rolled_back"; p["verification_digest"]=""; p["verification_digest"]=M.sha(p); self.assertFalse(self.accepted(prod=p)["production_chain"]["verified"])
    def test_mutated_canonical_verifier_seal_is_rejected(self):
        p=canonical_prod(); p["certificate_digest"]="9"*64
        with self.assertRaises(M.ReleaseError): self.accepted(prod=p)
    def test_generic_verified_true_hardware_summary_is_rejected(self):
        r=self.accepted(hw=gate("hardware_operational")); self.assertFalse(r["hardware_operational"]["verified"]); self.assertTrue(r["hardware_operational"]["rejected_summary_only_evidence"])
    def test_test_identity_rejected(self):
        p=policy(); s=sig(p); s["mode"]="test"; s["test_identity"]=True; r=self.accepted(p,s); self.assertFalse(r["signing"]["verified"])
    def test_wrong_chain_timestamp_subject_rejected(self):
        for key,val in [("certificate_chain_valid",False),("timestamp_present",False),("signer_subject","CN=Wrong"),("code_signing_eku_present",False),("signtool_verify_ok",False)]:
            p=policy(); s=sig(p); s["artifacts"][0][key]=val; self.assertFalse(self.accepted(p,s)["signing"]["verified"],key)
    def test_post_sign_mutation_rejected(self):
        p=policy(); s=sig(p); s["artifacts"][0]["sha256"]="f"*64
        with self.assertRaises(M.ReleaseError): self.accepted(p,s)
    def test_partial_inventory_rejected(self):
        b=base(); b["artifacts"].pop(1)
        with self.assertRaises(M.ReleaseError): M.build(b,policy())
    def test_test_lifecycle_rejected(self): self.assertFalse(self.accepted(l=life(True))["installer_lifecycle"]["verified"])
    def test_missing_service_lifecycle_phase_rejected(self):
        l=life(); del l["phases"]["service_validated_running"]; self.assertFalse(self.accepted(l=l)["installer_lifecycle"]["verified"])
if __name__=="__main__": unittest.main()
