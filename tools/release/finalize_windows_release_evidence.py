#!/usr/bin/env python3
"""Fail-closed Windows production release decision for Issue #78."""
from __future__ import annotations
import argparse, hashlib, json, re, sys
from pathlib import Path
from typing import Any

H64=re.compile(r"^[0-9a-f]{64}$"); H40=re.compile(r"^[0-9a-f]{40}$")
class ReleaseError(RuntimeError): pass

def canon(v:Any)->bytes:return json.dumps(v,ensure_ascii=False,sort_keys=True,separators=(",",":")).encode()
def sha(v:Any)->str:return hashlib.sha256(canon(v)).hexdigest()
def load(p:Path|None):
    if p is None:return None
    v=json.loads(p.read_text(encoding="utf-8"))
    if not isinstance(v,dict):raise ReleaseError(f"object required: {p}")
    return v
def h64(v:Any,n:str)->str:
    if not isinstance(v,str) or not H64.fullmatch(v):raise ReleaseError(f"invalid sha256: {n}")
    return v

def policy_ok(p:dict)->None:
    if p.get("schema_version")!="0.1.0" or p.get("policy_id")!="ergaxiom.windows-production-release":raise ReleaseError("policy identity")
    s=p.get("signing",{}); q=p.get("packaging",{}); inv=p.get("shipping_inventory",{})
    if p.get("canonical_installer")!="nsis" or q.get("targets")!=["nsis"] or q.get("install_mode")!="perMachine" or q.get("allow_downgrades") is not False:raise ReleaseError("installer policy")
    if q.get("service_name")!="ErgaxiomProductionSigner" or q.get("uninstall_preserves_production_state") is not True:raise ReleaseError("service/state policy")
    if s.get("digest_algorithm")!="SHA256" or s.get("timestamp_protocol")!="RFC3161" or not str(s.get("timestamp_url","")).startswith("https://"):raise ReleaseError("signing policy")
    if s.get("require_online_revocation") is not True or s.get("reject_self_signed") is not True:raise ReleaseError("chain policy")
    pe={(x.get("artifact_id"),x.get("name"),x.get("build_input"),x.get("disposition")) for x in inv.get("signed_pe_artifacts",[]) if isinstance(x,dict)}
    if pe!={("desktop","ergaxiom-desktop.exe","apps/desktop/src-tauri","SHIPPED_EXECUTABLE"),("production_signer_service","ergaxiom-windows-production-signer-service.exe","apps/windows-production-signer-service","SHIPPED_EXECUTABLE")}:raise ReleaseError("PE inventory")
    linked={(x.get("artifact_id"),x.get("build_input"),x.get("disposition")) for x in inv.get("linked_runtime_inputs",[]) if isinstance(x,dict)}
    if linked!={("windows_uia_client","crates/windows-uia-client-runtime","LINKED_INTO_DESKTOP"),("windows_bridge","crates/windows-bridge-runtime","LINKED_INTO_DESKTOP"),("inkscape_adapter","crates/inkscape-adapter-runtime","LINKED_RUNTIME")}:raise ReleaseError("linked inventory")
    if inv.get("installer")!={"artifact_id":"windows_installer","format":"NSIS","filename_glob":"*-setup.exe","disposition":"SHIPPED_INSTALLER"}:raise ReleaseError("installer inventory")

def artifacts(base:dict,p:dict)->tuple[dict[str,str],str]:
    if base.get("release_eligible") is not False:raise ReleaseError("base manifest must be fail-closed")
    c=base.get("source",{}).get("commit")
    if not isinstance(c,str) or not H40.fullmatch(c):raise ReleaseError("source commit")
    out={}
    for a in base.get("artifacts",[]):
        if not isinstance(a,dict) or not isinstance(a.get("name"),str) or a["name"] in out:raise ReleaseError("artifact inventory")
        out[a["name"]]=h64(a.get("sha256"),a.get("name","artifact"))
    setups=[n for n in out if n.lower().endswith("-setup.exe")]
    required={x["name"] for x in p["shipping_inventory"]["signed_pe_artifacts"]}
    if len(setups)!=1 or set(out)!=(required|{setups[0]}):raise ReleaseError("partial/substituted release inventory")
    return out,setups[0]

def signing(ev:dict|None,p:dict,art:dict[str,str])->tuple[bool,dict|None]:
    if ev is None:return False,None
    if ev.get("schema_version")!="0.1.0" or ev.get("policy_sha256")!=sha(p):raise ReleaseError("signature evidence binding")
    rs=ev.get("artifacts",[]); m={r.get("name"):r for r in rs if isinstance(r,dict) and isinstance(r.get("name"),str)}
    if len(m)!=len(rs) or set(m)!=set(art):raise ReleaseError("signature inventory")
    for n,d in art.items():
        if h64(m[n].get("sha256"),n)!=d:raise ReleaseError(f"post-sign mutation: {n}")
    s=p["signing"]; resolved=s.get("identity_status")=="OWNER_APPROVED_PINNED" and isinstance(s.get("expected_subject"),str) and H64.fullmatch(str(s.get("expected_certificate_sha256","")))
    ok=bool(resolved and ev.get("mode")=="production" and ev.get("test_identity") is False)
    for r in m.values():
        ok &= all([r.get("authenticode_valid") is True,r.get("signtool_verify_ok") is True,r.get("certificate_chain_valid") is True,r.get("revocation_checked_online") is True,r.get("timestamp_present") is True,r.get("timestamp_chain_valid") is True,r.get("self_signed") is False,r.get("signer_subject")==s.get("expected_subject"),r.get("signer_certificate_sha256")==s.get("expected_certificate_sha256"),r.get("timestamp_url")==s.get("timestamp_url")])
    return bool(ok),{"verified":bool(ok),"test_identity":ev.get("test_identity"),"evidence_sha256":sha(ev)}

def lifecycle(ev:dict|None,c:str,n:str,d:str)->tuple[bool,dict|None]:
    if ev is None:return False,None
    if ev.get("schema_version")!="0.1.0" or ev.get("source_commit")!=c or ev.get("installer_name")!=n or ev.get("installer_sha256")!=d:raise ReleaseError("lifecycle binding")
    req=["clean_install","upgrade","downgrade_rejected","interrupted_upgrade_preserved_state","recovery_install","uninstall","production_state_preserved"]
    ok=ev.get("test_mode") is False and all(ev.get("phases",{}).get(x) is True for x in req)
    return ok,{"verified":ok,"test_mode":ev.get("test_mode"),"evidence_sha256":sha(ev)}

def external(ev:dict|None,g:str,c:str)->tuple[bool,dict|None]:
    if ev is None:return False,None
    ok=ev.get("schema_version")=="0.1.0" and ev.get("gate")==g and ev.get("source_commit")==c and ev.get("verified") is True and bool(ev.get("evidence_artifacts"))
    if ok:
        for a in ev["evidence_artifacts"]:h64(a.get("sha256"),g)
    return bool(ok),{"verified":bool(ok),"evidence_sha256":sha(ev)}
def license_gate(ev:dict|None,p:dict,c:str)->tuple[bool,dict|None]:
    lp=p.get("license",{}); resolved=lp.get("owner_decision_status")=="APPROVED" and bool(lp.get("spdx_expression"))
    ok=bool(resolved and ev and ev.get("schema_version")=="0.1.0" and ev.get("source_commit")==c and ev.get("owner_approved") is True and ev.get("spdx_expression")==lp.get("spdx_expression"))
    return ok,None if ev is None else {"verified":ok,"spdx_expression":ev.get("spdx_expression"),"evidence_sha256":sha(ev)}

def build(base,p,sig=None,life=None,prod=None,hw=None,lic=None):
    policy_ok(p); art,ins=artifacts(base,p); c=base["source"]["commit"]
    so,ss=signing(sig,p,art); lo,ls=lifecycle(life,c,ins,art[ins]); po,ps=external(prod,"production_chain",c); ho,hs=external(hw,"hardware_operational",c); xo,xs=license_gate(lic,p,c)
    b=[]
    if p["signing"].get("identity_status")!="OWNER_APPROVED_PINNED":b.append("SIGNING_IDENTITY_POLICY_UNRESOLVED")
    if not so:b += ["AUTHENTICODE_NOT_VERIFIED","TRUSTED_TIMESTAMP_NOT_VERIFIED","CERTIFICATE_CHAIN_NOT_VERIFIED","SIGNING_IDENTITY_NOT_VERIFIED"]
    if not lo:b.append("INSTALLER_LIFECYCLE_NOT_VERIFIED")
    if not po:b.append("PRODUCTION_CHAIN_EVIDENCE_NOT_VERIFIED")
    if not ho:b.append("HARDWARE_OPERATIONAL_EVIDENCE_NOT_VERIFIED")
    if not xo:b.append("DISTRIBUTION_LICENSE_NOT_APPROVED")
    b=sorted(set(b))
    return {"schema_version":"0.1.0","product":base.get("product"),"source":base["source"],"toolchain":base.get("toolchain"),"artifacts":base["artifacts"],"sbom":base.get("sbom"),"windows_release_policy":{"policy_id":p["policy_id"],"sha256":sha(p),"canonical_installer":"nsis"},"signing":ss,"installer_provenance":{"installer_name":ins,"installer_sha256":art[ins],"verified":so and lo},"installer_lifecycle":ls,"production_chain":ps,"hardware_operational":hs,"distribution_license":xs,"release_eligible":not b,"blocking_reasons":b}

def main(argv=None):
    ap=argparse.ArgumentParser(); ap.add_argument("--base-manifest",type=Path,required=True); ap.add_argument("--policy",type=Path,required=True); ap.add_argument("--signature-evidence",type=Path); ap.add_argument("--lifecycle-evidence",type=Path); ap.add_argument("--production-chain-evidence",type=Path); ap.add_argument("--hardware-operational-evidence",type=Path); ap.add_argument("--license-decision",type=Path); ap.add_argument("--output",type=Path,required=True); a=ap.parse_args(argv)
    try:
        out=build(load(a.base_manifest),load(a.policy),load(a.signature_evidence),load(a.lifecycle_evidence),load(a.production_chain_evidence),load(a.hardware_operational_evidence),load(a.license_decision)); a.output.parent.mkdir(parents=True,exist_ok=True); a.output.write_text(json.dumps(out,sort_keys=True,indent=2)+"\n",encoding="utf-8"); return 0
    except (OSError,json.JSONDecodeError,ReleaseError) as e: print(f"final Windows release evidence failed: {e}",file=sys.stderr); return 1
if __name__=="__main__":raise SystemExit(main())
