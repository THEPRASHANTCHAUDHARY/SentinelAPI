(() => {
  const byId = id => document.getElementById(id);
  const wait = ms => new Promise(resolve => setTimeout(resolve, ms));
  let allowedTargets = [];
  let backendReady = false;
  let scanInProgress = false;

  function showError(message) { const box=byId("scan-error"); if(box){box.hidden=false;box.textContent=message;} window.dispatchEvent(new CustomEvent("sentinelapi:scan-error",{detail:message})); }
  function statusLabel(value) { const el=byId("scan-status"); if(el)el.textContent=String(value||"idle").toUpperCase(); window.dispatchEvent(new CustomEvent("sentinelapi:scan-state",{detail:value||"idle"})); }
  function renderTerminal(scan) {
    const box=byId("scan-terminal"); if(!box)return; box.replaceChildren();
    const rows=[["SCAN STATUS",scan.status||"idle"],["STAGE",scan.stage||"Waiting for scan"],["ENDPOINTS",scan.endpoint_count??0],["FINDINGS",scan.finding_count??0]];
    for(const [label,value] of rows){const line=document.createElement("div");const heading=document.createElement("span");heading.className="green";heading.textContent=`${label} `;line.append(heading,document.createTextNode(String(value)));box.append(line);}
    if(scan.error){const error=document.createElement("div");error.className="orange";error.textContent=scan.error;box.append(error);}
  }
  function renderEndpoints(scan) {
    const host=byId("scan-endpoints");if(!host)return;host.replaceChildren();
    if(!scan.endpoints?.length){host.textContent=scan.status==="completed"?"No endpoints discovered.":"No endpoints discovered yet.";return;}
    for(const endpoint of scan.endpoints){const row=document.createElement("div");row.className="finding";const header=document.createElement("div");header.className="finding-top";const method=document.createElement("span");method.textContent=endpoint.method;const path=document.createElement("span");path.textContent=endpoint.path;header.append(method,path);row.append(header);host.append(row);}
  }
  function renderFindings(scan) {
    const host=byId("scan-findings");if(!host)return;host.replaceChildren();
    if(scan.status==="completed"&&!scan.findings?.length){host.textContent="No vulnerabilities detected by the selected checks.";return;}
    if(!scan.findings?.length){host.textContent="Findings will appear when scan evidence is available.";return;}
    for(const finding of scan.findings){
      const card=document.createElement("details");card.className="finding";const summary=document.createElement("summary");summary.className="finding-top";
      const title=document.createElement("span");title.textContent=`${finding.type} | ${finding.method} ${finding.endpoint}`;
      const severity=document.createElement("span");severity.className="sev";severity.dataset.severity=finding.severity;severity.textContent=finding.severity;summary.append(title,severity);card.append(summary);
      const add=(label,value)=>{if(value==null||value==="")return;const p=document.createElement("p");const b=document.createElement("strong");b.textContent=`${label}: `;p.append(b,document.createTextNode(typeof value==="string"?value:JSON.stringify(value,null,2)));card.append(p);};
      add("Confidence",finding.confidence);add("Description",finding.description);add("Evidence",finding.evidence);add("PoC",finding.poc);add("Remediation",finding.remediation);host.append(card);
    }
  }
  function update(scan) {
    statusLabel(scan.status);renderTerminal(scan);renderEndpoints(scan);renderFindings(scan);
    const count=byId("scan-endpoint-count");if(count)count.textContent=String(scan.endpoint_count??0);
    const stage=byId("scan-stage");if(stage)stage.textContent=scan.stage||scan.status||"idle";
    window.dispatchEvent(new CustomEvent("sentinelapi:scan-update", { detail: scan }));
  }
  function resetResults() {
    const error=byId("scan-error");if(error){error.hidden=true;error.textContent="";}
    window.dispatchEvent(new CustomEvent("sentinelapi:scan-error", { detail: "" }));
    update({status:"validating",stage:"Validating the configured scan request.",endpoint_count:0,finding_count:0,endpoints:[],findings:[]});
  }
  async function watchScan(scan) {
    const startedAt=Date.now();let current=scan;
    while(["queued","running"].includes(current.status)){
      if(Date.now()-startedAt>600000)throw new Error("Scan status timed out. Reload the page to resume polling.");
      await wait(1000);current=await window.SentinelAPI.getScan(scan.id);update(current);
    }
    return current;
  }
  async function startScan(button,idleLabel) {
    if(scanInProgress)return;scanInProgress=true;button.disabled=true;button.textContent="SCANNING...";resetResults();let scanCreated=false;
    try {
      let health;
      try { health=await window.SentinelAPI.health(); backendReady=true; }
      catch { backendReady=false; const connection=byId("scan-health"); if(connection)connection.textContent="UNAVAILABLE"; throw new Error("SentinelAPI scanner is unavailable. Start the local backend and retry."); }
      allowedTargets=health.allowed_targets||[];
      const connection=byId("scan-health"); if(connection)connection.textContent="AVAILABLE";
      const environment=document.querySelector(".form select:not(#scan-identity)");
      if(!environment||environment.value!=="local-sandbox")throw new Error("Select the authorized local sandbox environment.");
      const specUrl=byId("scan-spec").value.trim();let parsed;try{parsed=new URL(specUrl);}catch{throw new Error("Enter a valid OpenAPI URL served by an authorized sandbox.");}
      if(parsed.protocol!=="http:"||parsed.username||parsed.password||parsed.search||parsed.hash||!allowedTargets.includes(parsed.origin))throw new Error("Target outside the configured authorized scan boundary.");
      const testClasses=[...document.querySelectorAll("[data-test-class]:checked")].map(input=>input.dataset.testClass);
      if(!testClasses.length)throw new Error("Select at least one test class.");
      let created;
      try { created=await window.SentinelAPI.createScan({target:parsed.origin,spec_url:parsed.href,identity:byId("scan-identity")?.value||"user-a",test_classes:testClasses}); }
      catch(error) {
        if((error.message||"").includes("scanner is unavailable"))throw error;
        throw new Error("Unable to start scan. Check that the SentinelAPI backend is running.");
      }
      scanCreated=true;update(created);const final=await watchScan(created);if(final.status==="failed")showError(final.error||"Scan failed. Correct the input and retry.");
      button.dataset.scanResult=final.status==="completed"?"completed":"failed";
    }catch(error){showError(error.message||"Unable to start scan.");if(!scanCreated)statusLabel("failed");button.dataset.scanResult="failed";}
    finally{button.disabled=false;button.textContent=button.dataset.scanResult==="completed"?"SCAN COMPLETE":button.dataset.scanResult==="failed"?"RETRY SCAN \u2197":idleLabel;scanInProgress=false;}
  }
  async function init() {
    const button=byId("start-scan");if(!button)return;const idleLabel=button.textContent.trim();button.addEventListener("click",event=>{event.preventDefault();startScan(button,idleLabel);});
    const query=new URLSearchParams(location.search);if(query.has("spec")){try{byId("scan-spec").value=new URL(query.get("spec")).href;}catch{}}
    try{const health=await window.SentinelAPI.health();allowedTargets=health.allowed_targets||[];backendReady=true;const el=byId("scan-health");if(el)el.textContent="AVAILABLE";}
    catch(error){const el=byId("scan-health");if(el)el.textContent="UNAVAILABLE";showError(error.message);}
    const history=await window.SentinelAPI.listScans().catch(()=>null);if(!history?.scans?.length)return;
    const latest=history.scans[0];update(latest);
    if(latest.status==="failed")showError(latest.error||"Scan failed.");
    if(["queued","running"].includes(latest.status)){scanInProgress=true;button.disabled=true;button.textContent="SCANNING...";try{const final=await watchScan(latest);if(final.status==="failed")showError(final.error||"Scan failed.");}catch(error){showError(error.message);}finally{button.disabled=false;button.textContent=idleLabel;scanInProgress=false;}}
  }
  if(document.readyState==="loading")document.addEventListener("DOMContentLoaded",init);else init();
})();