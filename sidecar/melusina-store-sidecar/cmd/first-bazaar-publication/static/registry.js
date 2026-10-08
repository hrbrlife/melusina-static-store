/* Exact devnet registry maintenance. Browser and outside-page signer share this policy. */
"use strict";
(() => {
  const W = globalThis.solanaWeb3;
  const C = Object.freeze({
    schema: "melusina.msb-registry-store-control.v1", origin: "http://127.0.0.1:9200",
    rpc: "https://api.devnet.solana.com", genesis: "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG",
    program: "7anRCW8UAFwdSAAxkrK7TmptukNKY74nZrNPfRKzzWLb",
    programData: "2Xp8pencUGdrkorjZcnUd3FePCkXXpXTN5no54PRoDuY",
    authority: "ANaEQo267D4QN9jjmxQcUHHScPgdxi2d1PTKh6kuX2tp",
    loader: "BPFLoaderUpgradeab1e11111111111111111111111",
    source: "b5d5e39f3efa36c7efa480251fcaab52f4f0ba62",
    sourceBase: "99b2c09cf5f1866a76258dd11626866929c5acba",
    artifactHash: "ef8fbd18f77474c979971daae3a881dd4f0520428dd1fea02f0ec5c91d1e1f85",
    artifactSize: 3979104, baseHash: "7c72a2c038b6a8dcc96f0cb9b6e2e090c8c3cca1dcf225e995fecd6da0732773",
    baseSize: 3814256, baseSlot: 493862091, chunkSize: 1000,
    bufferSeed: "ef8fbd18f77474c979971daae3a881dd",
    maxBufferRent: 28000000000, feeReserve: 100000000,
  });
  const pk = x => new W.PublicKey(x);
  const equal = (a,b) => a.length === b.length && a.every((v,i) => v === b[i]);
  const hex = b => [...b].map(x=>x.toString(16).padStart(2,"0")).join("");
  const hash = async b => hex(new Uint8Array(await crypto.subtle.digest("SHA-256",b)));
  const concat = (...parts) => { const out=new Uint8Array(parts.reduce((n,p)=>n+p.length,0));let i=0;for(const p of parts){out.set(p,i);i+=p.length;}return out; };
  const u32 = n => { if(!Number.isSafeInteger(n)||n<0||n>0xffffffff)throw Error("invalid u32");const b=new Uint8Array(4);new DataView(b.buffer).setUint32(0,n,true);return b; };
  const u64 = n => { if(!Number.isSafeInteger(n)||n<0)throw Error("invalid u64");const b=new Uint8Array(8);new DataView(b.buffer).setBigUint64(0,BigInt(n),true);return b; };
  const read32 = (b,n=0) => new DataView(b.buffer,b.byteOffset,b.byteLength).getUint32(n,true);
  const read64 = (b,n=0) => Number(new DataView(b.buffer,b.byteOffset,b.byteLength).getBigUint64(n,true));
  const key = (pubkey,isSigner=false,isWritable=false) => ({pubkey:pk(pubkey),isSigner,isWritable});
  const loader = (data,keys) => new W.TransactionInstruction({programId:pk(C.loader),data,keys});
  const bufferAddress = () => W.PublicKey.createWithSeed(pk(C.authority),C.bufferSeed,pk(C.loader));
  async function fetchRPC(url,options,transport=fetch,wait=ms=>new Promise(r=>setTimeout(r,ms))) {
    if(String(url)!==C.rpc)throw Error("wrong registry RPC");
    const fixed={...options};
    // Reuse the exact body (including a signed transaction, if present). No new
    // transaction or signature is minted when a transport response is uncertain.
    for(let attempt=0;attempt<5;attempt++){
      const r=await transport(url,{...fixed,redirect:"error",signal:AbortSignal.timeout(25000)});
      if(![429,503,504].includes(r.status)||attempt===4)return r;
      const retry=Number(r.headers.get("retry-after"));
      const pause=Math.max(1500*2**attempt,Number.isFinite(retry)&&retry>0?Math.min(30000,retry*1000):0);
      await r.arrayBuffer();await wait(pause);
    }
  }
  function connection() {
    return new W.Connection(C.rpc,{commitment:"finalized",disableRetryOnRateLimit:true,
      fetch: (url,options) => fetchRPC(url,options)});
  }
  async function artifact(bytes) {
    if(!(bytes instanceof Uint8Array)||bytes.length!==C.artifactSize||await hash(bytes)!==C.artifactHash)throw Error("unreviewed registry artifact");
    return bytes;
  }
  function owned(info, owner, executable, label) {
    if(!info||info.owner.toBase58()!==owner||info.executable!==executable)throw Error(label+" owner or executable mismatch");
    return new Uint8Array(info.data);
  }
  async function classifyProgram(info) {
    const d=owned(info,C.loader,false,"ProgramData");
    if(d.length<45||read32(d)!==3||d[12]!==1||!equal(d.slice(13,45),pk(C.authority).toBytes()))throw Error("registry upgrade authority changed");
    const slot=read64(d,4), body=d.slice(45);
    if(body.length===C.artifactSize && await hash(body)===C.artifactHash)return {state:"complete",slot,bytes:body.length};
    const extended=body.length===C.artifactSize;
    if(body.length!==C.baseSize&&!extended)throw Error("registry allocation differs from reviewed base/candidate");
    if(await hash(body.slice(0,C.baseSize))!==C.baseHash || body.slice(C.baseSize).some(x=>x!==0))throw Error("registry deployed code differs from reviewed predecessor");
    if(!extended && slot!==C.baseSlot)throw Error("registry predecessor deployment slot changed");
    return {state:extended?"extended":"base",slot,bytes:body.length};
  }
  async function context(conn=connection()) {
    if(await conn.getGenesisHash()!==C.genesis)throw Error("wrong Solana cluster");
    const buffer=await bufferAddress();
    const r=await conn.getMultipleAccountsInfoAndContext([pk(C.program),pk(C.programData),pk(C.authority),buffer],{commitment:"finalized"});
    const p=owned(r.value[0],C.loader,true,"Program");
    if(p.length!==36||read32(p)!==2||!equal(p.slice(4),pk(C.programData).toBytes()))throw Error("program mapping changed");
    const program=await classifyProgram(r.value[1]);
    const wallet=owned(r.value[2],W.SystemProgram.programId.toBase58(),false,"authority");
    if(wallet.length!==0)throw Error("authority is not a system wallet");
    let bufferBytes=null;
    if(r.value[3]) {
      const b=owned(r.value[3],C.loader,false,"Buffer");
      if(b.length!==37+C.artifactSize||read32(b)!==1||b[4]!==1||!equal(b.slice(5,37),pk(C.authority).toBytes()))throw Error("candidate buffer layout or authority changed");
      bufferBytes=b.slice(37);
    }
    return {connection:conn,slot:r.context.slot,program,buffer:buffer.toBase58(),bufferBytes,
      balance:r.value[2].lamports,programLamports:r.value[1].lamports};
  }
  async function createInstructions(rent) {
    if(!Number.isSafeInteger(rent)||rent<=0||rent>C.maxBufferRent)throw Error("buffer rent exceeds fixed reviewed limit");
    const buffer=await bufferAddress();
    const allocation=W.SystemProgram.createAccountWithSeed({fromPubkey:pk(C.authority),newAccountPubkey:buffer,basePubkey:pk(C.authority),
      seed:C.bufferSeed,lamports:rent,space:C.artifactSize+37,programId:pk(C.loader)});
    // Keep the Rust SDK's explicit base-authority account, even when it is the payer.
    allocation.keys.push(key(C.authority,true));
    return [allocation,loader(u32(0),[key(buffer,false,true),key(C.authority)])];
  }
  async function writeInstruction(bytes,offset) {
    if(!Number.isInteger(offset)||offset<0||offset>=C.artifactSize||offset%C.chunkSize!==0||bytes.length!==C.artifactSize)throw Error("invalid reviewed chunk offset");
    const part=bytes.slice(offset,Math.min(offset+C.chunkSize,bytes.length));
    return loader(concat(u32(1),u32(offset),u64(part.length),part),[key(await bufferAddress(),false,true),key(C.authority,true)]);
  }
  function extendInstruction() {
    return loader(concat(u32(6),u32(C.artifactSize-C.baseSize)),[key(C.programData,false,true),key(C.program,false,true),key(W.SystemProgram.programId),key(C.authority,true,true)]);
  }
  async function upgradeInstruction() {
    return loader(u32(3),[key(C.programData,false,true),key(C.program,false,true),key(await bufferAddress(),false,true),key(C.authority,false,true),key(W.SYSVAR_RENT_PUBKEY),key(W.SYSVAR_CLOCK_PUBKEY),key(C.authority,true)]);
  }
  function outer(instructions,blockhash) {
    const t=new W.VersionedTransaction(new W.TransactionMessage({payerKey:pk(C.authority),recentBlockhash:blockhash,instructions}).compileToV0Message());
    if(t.serialize().length>1232)throw Error("registry transaction exceeds packet limit");return t;
  }
  async function authorize(action,bytes,conn=connection()) {
    const s=await context(conn);if(s.program.state==="complete")throw Error("candidate is already deployed");
    let instructions;
    if(action==="create") {
      if(s.bufferBytes)throw Error("buffer already exists; verify and resume it");
      const rent=await conn.getMinimumBalanceForRentExemption(C.artifactSize+37,"finalized");
      if(s.balance<rent+C.feeReserve)throw Error("existing authority lacks buffer rent and fee reserve");
      instructions=await createInstructions(rent);
    } else if(action==="upload") {
      await artifact(bytes);if(!s.bufferBytes)throw Error("create the fixed buffer first");
    } else if(action==="extend"||action==="upgrade") {
      if(!s.bufferBytes||await hash(s.bufferBytes)!==C.artifactHash)throw Error("uploaded buffer does not match the complete reviewed ELF");
      if(action==="extend") {
        if(s.program.state!=="base")throw Error("program allocation already extended");
        const rent=await conn.getMinimumBalanceForRentExemption(C.artifactSize+45,"finalized");
        if(s.balance<Math.max(0,rent-s.programLamports)+C.feeReserve)throw Error("insufficient extension rent reserve");
        instructions=[extendInstruction()];
      } else {
        if(s.program.state!=="extended")throw Error("extend program allocation first");
        instructions=[await upgradeInstruction()];
      }
    } else throw Error("unreviewed registry operation");
    return {context:s,instructions};
  }
  async function simulate(conn,tx) {
    const r=await conn.simulateTransaction(tx,{sigVerify:false,commitment:"confirmed"});
    if(r.value.err)throw Error("registry simulation refused: "+JSON.stringify({error:r.value.err,logs:r.value.logs}));return r.value;
  }
  globalThis.MelusinaMSBRegistry=Object.freeze({constants:C,connection,fetchRPC,context,classifyProgram,artifact,bufferAddress,createInstructions,writeInstruction,extendInstruction,upgradeInstruction,outer,authorize,simulate,hash,hex,equal});
})();
