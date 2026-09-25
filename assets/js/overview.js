(() => {
  const set=(id,value)=>{const node=document.getElementById(id);if(node)node.textContent=value;};
  let pollTimer=null;
  function render(scan){
    if(!scan){
      set("overview-empty","No scans yet");set("overview-status","IDLE");
      set("overview-stage","Run an authorized sandbox scan to see live results here.");
      set("overview-endpoints","?");set("overview-findings","?");
      const list=document.getElementById("overview-findings-list");if(list)list.replaceChildren();return;
    }
    set("overview-empty",scan.status==="failed"?(scan.error||"Scan failed."):"");
    set("overview-status",String(scan.status||"unknown").toUpperCase());
    set("overview-stage",scan.status==="failed"?(scan.error||scan.stage||"Scan failed"):scan.stage||"");
    set("overview-endpoints",String(scan.endpoint_count??0));set("overview-findings",String(scan.finding_count??0));
    const host=document.getElementById("overview-findings-list");
    if(host){host.replaceChildren();
      if(!(scan.findings||[]).length&&scan.status==="completed"){
        const empty=document.createElement("p");empty.className="finding";empty.textContent="No vulnerabilities detected in the latest scan.";host.append(empty);
      }
      for(const finding of scan.findings||[]){
        const row=document.createElement("div");row.className="finding";
        const landing=host.classList.contains("landing-findings");
        const header=document.createElement("div");header.className=landing?"finding-left":"finding-top";
        const label=document.createElement(landing?"div":"span");
        if(landing){const type=document.createElement("small");type.textContent=`${finding.severity} | ${finding.type}`;const route=document.createElement("b");route.textContent=`${finding.method} ${finding.endpoint}`;label.append(type,route);}
        else label.textContent=`${finding.type} | ${finding.method} ${finding.endpoint}`;
        const severity=document.createElement("span");severity.className=landing?"severity":"sev";severity.dataset.severity=finding.severity;severity.textContent=finding.severity;
        if(landing){const icon=document.createElement("div");icon.className="finding-icon";icon.textContent="!";header.append(icon,label);row.append(header,severity);}
        else{header.append(label,severity);row.append(header);const description=document.createElement("p");description.textContent=finding.description||"";row.append(description);}
        host.append(row);
      }
    }
    if(pollTimer){clearTimeout(pollTimer);pollTimer=null;}
    if(["queued","running"].includes(scan.status))pollTimer=setTimeout(loadLatest,3000);
  }
  async function loadLatest(){
    try{
      const user=await window.SentinelAuth?.getCurrentUser();
      set("backend-status","CONNECTED");set("backend-status-detail","Connected to the local SentinelAPI backend.");
      if(!user){render(null);return;}
      const response=await window.SentinelAPI.listScans();render(response.scans?.[0]||null);
    }catch{set("backend-status","UNAVAILABLE");set("backend-status-detail","SentinelAPI scanner is unavailable.");set("overview-empty","SentinelAPI scanner is unavailable.");}
  }
  window.addEventListener("sentinelapi:scan-update",event=>render(event.detail));
  window.addEventListener("sentinelapi:scan-error",event=>{if(event.detail)set("overview-empty",event.detail);});
  window.addEventListener("sentinelapi:scan-state",event=>set("overview-status",String(event.detail||"idle").toUpperCase()));
  if(document.readyState==="loading")document.addEventListener("DOMContentLoaded",loadLatest);else loadLatest();
})();