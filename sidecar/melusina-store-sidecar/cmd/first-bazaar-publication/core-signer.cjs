#!/usr/bin/env node
"use strict";
// Purpose-bound wallet bridge. This process never broadcasts a transaction.
const fs=require("node:fs"),path=require("node:path"),vm=require("node:vm"),crypto=require("node:crypto");
const ROOT=__dirname,WebSocket=require("./vendor/ws");
const {base58,parseSolanaWireTransaction}=require("./solana-wire.cjs");
const ORIGIN="http://127.0.0.1:18510",BINDING="__melusinaFirstBazaarSign";
const WEB3_SHA="021e88bb4b21b95f3b0e83238ec88aedf06f406ba4a66e8cea951cca218539ad";
const PROTOCOL_SHA="dadd34a84e169d50d8d8756c194adafddc2fc1c28eb50508106022f86f78cd54";
const SETUP_PROTOCOL_SHA="4cfebd53428833e8d65fd36c48f1a443d489f0b2b5fcaeec9eb3d4d841e8d163";
const RUNTIME_PROTOCOL_SHA="1e4a35ad8ae77b4bc34d85bb5fb968d2a564e8c3abce399184524bc3e59ce53d";
const sha=b=>crypto.createHash("sha256").update(b).digest("hex");
function options(argv,now=Math.floor(Date.now()/1000)){
  const names=["--action","--target","--key-file","--plan-file","--member","--index","--expires-at","--artifact"],p={};
  for(let i=0;i<argv.length;i+=2){if(!names.includes(argv[i])||!argv[i+1]||p[argv[i]])throw Error("invalid exact first app approval signer option");p[argv[i]]=argv[i+1];}
  if(names.some(k=>!p[k])||!["create","propose","approve","execute"].includes(p["--action"]))throw Error("one exact first Bazaar release approval operation is required");
  const expiresAt=Number(p["--expires-at"]);if(!Number.isSafeInteger(expiresAt)||expiresAt<=now||expiresAt>now+600)throw Error("first app approval signer requires an expiry within ten minutes");
  if(!/^[A-Za-z0-9_-]{1,128}$/.test(p["--target"])||![p["--key-file"],p["--plan-file"],p["--artifact"]].every(path.isAbsolute)||!/^([1-9][0-9]{0,15})$/.test(p["--index"])||BigInt(p["--index"])>BigInt(Number.MAX_SAFE_INTEGER))throw Error("exact browser target, absolute owned files and one bounded Core index are required");
  return {action:p["--action"],target:p["--target"],keyFile:p["--key-file"],planFile:p["--plan-file"],artifact:p["--artifact"],member:p["--member"],index:BigInt(p["--index"]),expiresAt};
}
function pinned(name,digest){const fd=fs.openSync(name,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);try{const st=fs.fstatSync(fd);if(!st.isFile()||st.size>4*1024*1024)throw Error("invalid public protocol asset");const b=fs.readFileSync(fd);if(sha(b)!==digest)throw Error("protocol asset differs from the reviewed signer pin");return b.toString("utf8");}finally{fs.closeSync(fd);}}
async function rpc(url,o){
  if(String(url)!=="https://api.devnet.solana.com"||o?.method!=="POST")throw Error("signer RPC is devnet read-only");
  const p=JSON.parse(o.body);if(Array.isArray(p)||!["getGenesisHash","getMultipleAccounts","getMinimumBalanceForRentExemption","isBlockhashValid","simulateTransaction"].includes(p.method))throw Error("signer cannot submit transactions or arbitrary RPC calls");
  return fetch(url,{...o,redirect:"error",signal:AbortSignal.timeout(25000)});
}
function protocol(){const c=vm.createContext({crypto:crypto.webcrypto,console,TextEncoder,TextDecoder,Uint8Array,ArrayBuffer,Buffer,BigInt,atob,btoa,setTimeout,clearTimeout,AbortSignal,fetch:rpc},{codeGeneration:{strings:false,wasm:false}});
  vm.runInContext(pinned(path.join(ROOT,"static/web3.js"),WEB3_SHA),c,{timeout:10000});
  vm.runInContext(pinned(path.join(__dirname,"static/registry.js"),PROTOCOL_SHA),c,{timeout:1000});
  vm.runInContext(pinned(path.join(__dirname,"static/core.js"),SETUP_PROTOCOL_SHA),c,{timeout:1000});vm.runInContext(pinned(path.join(__dirname,"static/protocol.js"),RUNTIME_PROTOCOL_SHA),c,{timeout:1000});return c.MelusinaFirstBazaar;
}
function ownedFile(filename,max,privateFile){const fd=fs.openSync(filename,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);try{const st=fs.fstatSync(fd);if(!st.isFile()||st.uid!==process.getuid()||st.nlink!==1||st.size>max||(st.mode&(privateFile?0o077:0o022)))throw Error("signer input is not an owned protected regular file");return fs.readFileSync(fd);}finally{fs.closeSync(fd);}}
function signer(filename,expected){const raw=JSON.parse(ownedFile(filename,4096,true));if(!Array.isArray(raw)||raw.length!==64||raw.some(v=>!Number.isInteger(v)||v<0||v>255))throw Error("invalid existing Solana keypair");
  const secret=Buffer.from(raw.slice(0,32)),privateKey=crypto.createPrivateKey({key:Buffer.concat([Buffer.from("302e020100300506032b657004220420","hex"),secret]),format:"der",type:"pkcs8"});secret.fill(0);
  const publicKey=crypto.createPublicKey(privateKey),b=publicKey.export({format:"der",type:"spki"}).subarray(-32);
  if(base58(b)!==expected||!b.equals(Buffer.from(raw.slice(32))))throw Error("existing key is not the exact original Core member");raw.fill(0);return {privateKey,publicKey};
}
function exactWire(wire,H,instructions,member){
  const p=parseSolanaWireTransaction(wire);
  if(!H.constants.coreMembers.includes(member)||p.version!==0||p.signatures!==1||p.numRequiredSignatures!==1||p.feePayer!==member||p.addressTableLookups!==0||wire.length>1232||wire.subarray(p.signatureOffset,p.signatureOffset+64).some(v=>v!==0))throw Error("setup signing requires one unsigned exact-member v0 message");
  const exact=H.outer(member,instructions,p.recentBlockhash);
  if(!Buffer.from(exact.message.serialize()).equals(wire.subarray(p.messageOffset)))throw Error("message differs from the exact governed first Bazaar release approval operation");
  return {parsed:p,transaction:exact};
}
function gate(p,H,plan,key,{now=()=>Math.floor(Date.now()/1000),checkDocument=async()=>{},conn=H.connection()}={}){
  let used=false;
  return async request=>{
    if(used||now()>=p.expiresAt)throw Error("one-use first Bazaar release approval signer is used or expired");
    if(!request||Object.keys(request).sort().join(",")!=="account,action,id,offset,origin,transactionBase64"||request.origin!==ORIGIN||request.action!==p.action||request.account!==p.member||request.offset!==Number(p.index)||!Number.isSafeInteger(request.id)||request.id<1||typeof request.transactionBase64!=="string")throw Error("request is outside exact reviewed setup scope");
    used=true;await checkDocument();const instructions=(await H.authorize(p.action,plan,p.index,p.member,conn)).instructions;
    const wire=Buffer.from(request.transactionBase64,"base64");if(wire.toString("base64")!==request.transactionBase64)throw Error("noncanonical transaction base64");
    const {parsed,transaction}=exactWire(wire,H,instructions,p.member);if(!(await conn.isBlockhashValid(parsed.recentBlockhash,"confirmed"))?.value)throw Error("expired blockhash");await H.simulate(conn,transaction);
    await checkDocument();if(now()>=p.expiresAt)throw Error("first app approval signer expired during verification");
    const signed=Buffer.from(wire),signature=crypto.sign(null,signed.subarray(parsed.messageOffset),key.privateKey);if(!crypto.verify(null,signed.subarray(parsed.messageOffset),key.publicKey,signature))throw Error("local signature verification failed");signature.copy(signed,parsed.signatureOffset);return {signed,messageHash:parsed.messageSha256,offset:Number(p.index)};
  };
}
function providerSource(p,C){return `(()=>{
  if(location.href!==${JSON.stringify(ORIGIN+"/")}||window!==window.top)throw Error('wrong registry document');
  const account=${JSON.stringify(C.authority)},action=${JSON.stringify(p.action)},pending=new Map();let next=0,expired=false;
  const expire=()=>{expired=true;for(const p of pending.values())p.reject(Error("Original first Bazaar release signer expired; verify before re-arming."));pending.clear();};
  setTimeout(expire,Math.max(0,${p.expiresAt}*1000-Date.now()));
  const publicKey=Object.freeze({toBase58:()=>account,toString:()=>account});
  window.__melusinaFirstBazaarExpire=expire;
  window.__melusinaFirstBazaarResolve=(id,bytes,error)=>{const p=pending.get(id);if(!p)return;pending.delete(id);error?p.reject(Error(error)):p.resolve(solanaWeb3.VersionedTransaction.deserialize(Uint8Array.from(bytes)));};
  window.__melusinaFirstBazaarProvider=Object.freeze({publicKey,action,connect:async()=>{if(expired)throw Error("signer expired");return {publicKey};},signTransaction:(tx,s)=>{
    if(expired||Date.now()>=${p.expiresAt}*1000||location.href!==${JSON.stringify(ORIGIN+"/")}||s?.action!==action)throw Error('wrong registry operation');
    return new Promise((resolve,reject)=>{const id=++next;pending.set(id,{resolve,reject});let binary='';for(const b of tx.serialize())binary+=String.fromCharCode(b);window[${JSON.stringify(BINDING)}](JSON.stringify({id,origin:location.origin,action,offset:s.offset,account,transactionBase64:btoa(binary)}));});
  }});return {account,action};
})()`;}
async function main(argv){
  if(!["20","22","24"].includes(process.versions.node.split(".")[0]))throw Error("stable Node 20/22/24 required");
  const p=options(argv),H=protocol(),bytes=H.plan(ownedFile(p.planFile,131072,false).toString("utf8"));
  if(!H.constants.coreMembers.includes(p.member))throw Error("member is outside original Core authority");
  const artifact=ownedFile(p.artifact,H.constants.spkBytes+1,false);if(artifact.length!==H.constants.spkBytes||sha(artifact)!==H.constants.spkSHA)throw Error("artifact differs from the exact reviewed first Bazaar release");
  await H.authorize(p.action,bytes,p.index,p.member); // Public chain and artifact checks precede all key access.
  const meta=await (await fetch("http://127.0.0.1:9222/json/version",{redirect:"error",signal:AbortSignal.timeout(5000)})).json(),url=new URL(meta.webSocketDebuggerUrl);
  if(url.protocol!=="ws:"||url.hostname!=="127.0.0.1"||url.port!=="9222"||url.search||url.hash||url.username||url.password)throw Error("wrong owned Chrome endpoint");
  const ws=new WebSocket(url);await new Promise((r,j)=>{ws.once("open",r);ws.once("error",j);});
  let n=0,session,contextID,doneResolve;const waiting=new Map(),contexts=new Map(),done=new Promise(r=>doneResolve=r);
  const call=(method,params={},sid=session)=>new Promise((resolve,reject)=>{const id=++n,timer=setTimeout(()=>{waiting.delete(id);reject(Error("CDP timeout "+method));},10000);waiting.set(id,{resolve,reject,timer});ws.send(JSON.stringify({id,method,params,...(sid?{sessionId:sid}:{})}));});
  const checkDocument=async()=>{const r=await call("Runtime.evaluate",{expression:"({href:location.href,top:window===window.top})",returnByValue:true,contextId:contextID});if(r.exceptionDetails||r.result.value.href!==ORIGIN+"/"||!r.result.value.top)throw Error("original registry top-level document was lost");};
  let accept,handling=Promise.resolve();
  ws.on("message",data=>{
    const m=JSON.parse(data);
    if(m.id&&waiting.has(m.id)){const p=waiting.get(m.id);waiting.delete(m.id);clearTimeout(p.timer);m.error?p.reject(Error(m.error.message)):p.resolve(m.result);return;}
    if(m.sessionId!==session)return;
    if(m.method==="Runtime.executionContextCreated"&&m.params.context.auxData?.isDefault)contexts.set(m.params.context.id,m.params.context.auxData.frameId);
    if(contextID&&((m.method==="Runtime.executionContextDestroyed"&&m.params.executionContextId===contextID)||m.method==="Runtime.executionContextsCleared"))doneResolve();
    if(m.method!=="Runtime.bindingCalled"||m.params.name!==BINDING)return;
    handling=handling.then(async()=>{
      let id;
      try{if(m.params.executionContextId!==contextID||!accept)throw Error("signing request outside original context");const request=JSON.parse(m.params.payload);id=request.id;const out=await accept(request);await call("Runtime.evaluate",{expression:`window.__melusinaFirstBazaarResolve(${id},${JSON.stringify([...out.signed])},null)`,contextId:contextID});if(p.action!=="upload"||out.offset%100000===0)console.log(JSON.stringify({signed:true,action:p.action,offset:out.offset,messageHash:out.messageHash}));if(p.action!=="upload")doneResolve();}
      catch(e){console.error("Registry signer refused: "+e.message);if(Number.isSafeInteger(id))try{await call("Runtime.evaluate",{expression:`window.__melusinaFirstBazaarResolve(${id},null,${JSON.stringify(e.message)})`,contextId:contextID});}catch(_){}doneResolve();}
    });
  });
  let expiry;
  try{
    const t=(await call("Target.getTargetInfo",{targetId:p.target},null)).targetInfo;if(t.type!=="page"||t.url!==ORIGIN+"/")throw Error("wrong exact registry page");
    session=(await call("Target.attachToTarget",{targetId:p.target,flatten:true},null)).sessionId;await call("Page.enable");await call("Runtime.enable");
    const frame=(await call("Page.getFrameTree")).frameTree.frame.id;contextID=[...contexts].find(([,f])=>f===frame)?.[0];if(!contextID)throw Error("registry default top-level context missing");
    await checkDocument();const key=signer(p.keyFile,p.member);accept=gate(p,H,bytes,key,{checkDocument});
    await call("Runtime.addBinding",{name:BINDING,executionContextId:contextID});
    const r=await call("Runtime.evaluate",{expression:providerSource(p,{...H.constants,authority:p.member}),contextId:contextID,returnByValue:true});if(r.exceptionDetails)throw Error("registry provider injection failed");
    console.log(JSON.stringify({armed:true,action:p.action,target:p.target,authority:p.member,expiresAt:p.expiresAt}));
    expiry=setTimeout(doneResolve,Math.max(1,p.expiresAt*1000-Date.now()));await done;await handling;
  }finally{clearTimeout(expiry);for(const p of waiting.values())clearTimeout(p.timer);try{await call("Runtime.evaluate",{expression:"window.__melusinaFirstBazaarExpire?.()",contextId:contextID});await call("Runtime.removeBinding",{name:BINDING});}catch(_){}ws.close();}
}
module.exports={options,protocol,signer,exactWire,gate,providerSource};
if(require.main===module){const keepalive=setTimeout(()=>{console.error("first-release signer lifetime exceeded");process.exit(1);},660000);main(process.argv.slice(2)).catch(e=>{console.error(e.message);process.exitCode=1;}).finally(()=>clearTimeout(keepalive));}
