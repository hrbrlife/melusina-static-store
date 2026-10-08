"use strict";
// Read-only reuse of the reviewed original Core1985/R32 protocol. There is no
// key reader, signing capability, browser transport or transaction submission.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),vm=require('node:vm');
if(!['20','22','24'].includes(process.versions.node.split('.')[0])||process.argv.length!==2||!path.isAbsolute(process.argv[1]))throw Error('stable Node and original source root required');
const deadline=setTimeout(()=>{console.error('original authority readback timed out');process.exit(1);},55000);
const c=vm.createContext({crypto:crypto.webcrypto,console,TextEncoder,TextDecoder,Uint8Array,ArrayBuffer,Buffer,BigInt,atob,btoa,setTimeout,clearTimeout,AbortSignal,fetch:async(url,opts)=>{
 if(String(url)!=='https://api.devnet.solana.com'||opts?.method!=='POST')throw Error('read-only original devnet RPC required');
 const request=JSON.parse(opts.body);if(Array.isArray(request)||!['getGenesisHash','getMultipleAccounts'].includes(request.method))throw Error('non-observation RPC refused');
 return fetch(url,{...opts,redirect:'error',signal:AbortSignal.timeout(25000)});
}},{codeGeneration:{strings:false,wasm:false}});
for(const [name,pin] of [
 ['deploy-ui/static/vendor/web3.js-1.95.5.iife.min.js','021e88bb4b21b95f3b0e83238ec88aedf06f406ba4a66e8cea951cca218539ad'],
 ['msb-registry-upgrade/static/store-control-protocol.js','dadd34a84e169d50d8d8756c194adafddc2fc1c28eb50508106022f86f78cd54'],
 ['msb-registry-upgrade/static/store-policy-setup-protocol.js','4cfebd53428833e8d65fd36c48f1a443d489f0b2b5fcaeec9eb3d4d841e8d163'],
 ['msb-registry-upgrade/static/store-runtime-approval-protocol.js','70303e9a4f58643ffc51d18fca6686cd38a185b15fbb78a8177b6b083e4f5eed'],
 ['msb-registry-upgrade/static/store-runtime-identity-protocol.js','53cee56bd30bf119800e7cd311cd9e24c2ef6c3f9dc16b65187c10732faaafd1']
]){const fd=fs.openSync(path.join(process.argv[1],name),fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);let raw;try{const st=fs.fstatSync(fd);if(!st.isFile()||st.size>4*1024*1024)throw Error('invalid original protocol asset');raw=fs.readFileSync(fd);}finally{fs.closeSync(fd);}if(crypto.createHash('sha256').update(raw).digest('hex')!==pin)throw Error('original protocol asset changed');vm.runInContext(raw.toString('utf8'),c,{timeout:10000});}
(async()=>{const H=c.MelusinaStoreRuntimeIdentity,C=H.constants,p=H.plan(JSON.stringify({schema:C.schema,action:'update_original_store_identity',sourceCommit:C.sourceCommit,version:C.version,binarySHA256:C.binarySHA256,binaryBytes:C.binaryBytes,coreTransactionIndex:1985})),r=await H.context(p,1985n);if(!r.applied)throw Error('actual original R32 identity adoption is not finalized');console.log(JSON.stringify({schema:'melusina-original-store-publication-authority-readback-v1',slot:r.slot,coreSlot:r.coreSlot,index:1985,core:C.coreMultisig,proposalState:r.core.proposal.status,approved:r.core.proposal.approved,rootInstallAdmin:C.rootInstallAdmin,identity:C.identity,hash:r.hash,registeredAt:r.registeredAt}));})().catch(e=>{console.error(e.message);process.exitCode=1;}).finally(()=>clearTimeout(deadline));
