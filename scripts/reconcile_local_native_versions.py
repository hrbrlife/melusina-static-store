#!/usr/bin/env python3
"""Derive a new local catalog from actual saved native SPK verification outputs.
Never edits originals, serves files, installs, signs, or changes runtime state.
"""
import argparse,datetime,hashlib,json,os,pathlib,re,shutil

def digest(path):
    with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()

def native_fields(text):
    def match(pattern):
        result=re.search(pattern,text)
        if not result:raise ValueError('native verification field missing')
        return result.group(1)
    return {'appId':match(r'"appId"\s*:\s*"([a-z0-9]{52})"'),
            'packageId':match(r'"packageId"\s*:\s*"([a-f0-9]{32})"'),
            'versionNumber':int(match(r'"version"\s*:\s*(\d+)')),
            'version':json.loads(match(r'"marketingVersion"\s*:\s*\{\s*"defaultText"\s*:\s*("(?:\\.|[^"\\])*")'))}

def reconcile(manifest_path,audit_path,output):
    manifest=json.loads(manifest_path.read_text());audit=json.loads(audit_path.read_text())
    rows=manifest['selected'];actuals={a['slug']:a for a in audit['results']}
    if len(rows)!=35 or len(actuals)!=35 or len({a.get('upstreamAppId',a['appId']) for a in rows})!=35:
        raise ValueError('exact35 logical roster required')
    signatures=json.loads((audit_path.parent/'NATIVE-ALL35-SPK-VERIFICATION-03.json').read_text())
    if signatures['all35Verified'] is not True or signatures['native_binary_sha256']!='aa108e18623388591e3ddcaf84cd03d200b2170709aefbf9e4d50adb4311d9c8':
        raise ValueError('accepted native signature verification missing')
    signed={a['slug']:a for a in signatures['results']}
    checked=[]
    for row in rows:
        report=actuals[row['slug']];proof=report['actual'];evidence=(audit_path.parent/proof['source']).resolve()
        if not evidence.is_relative_to(audit_path.parent.resolve()):raise ValueError('evidence outside selected root')
        if row['slug']=='doc-bureau':
            native=json.loads(evidence.read_text())
            if native['native_verify_exit']!=0 or native['native_signature_verified'] is not True:raise ValueError('native verification not successful')
            native={k:native[k] for k in ['appId','packageId','versionNumber','version']}
        else:
            native=native_fields(evidence.read_text());signature=signed[row['slug']]
            if signature['nativeVerifyExit']!=0 or signature['identityMatches'] is not True or signature['appId']!=native['appId'] or signature['packageId']!=native['packageId'] or signature['versionNumber']!=native['versionNumber']:
                raise ValueError('actual successful native signature output required')
        if native!={'appId':row['appId'],'packageId':row['packageId'],'versionNumber':proof['versionNumber'],'version':proof['version']}:
            raise ValueError('native output disagrees with identity/version audit')
        source=pathlib.Path(row['spk']);meta_path=pathlib.Path(row['metadata']);meta=json.loads(meta_path.read_text())
        if source.is_symlink() or source.stat().st_size!=row['sizeBytes'] or digest(source)!=row['sha256'] or row['sha256'][:32]!=row['packageId']:
            raise ValueError('selected package bytes changed')
        if meta['appId']!=row['appId'] or meta['packageId']!=row['packageId']:raise ValueError('metadata identity changed')
        changed=meta.get('version')!=native['version'] or meta.get('versionNumber')!=native['versionNumber']
        checked.append((row,meta_path,meta,source,native,evidence,changed))
    output.mkdir(mode=0o755) # Exclusive; retain partial output on failure.
    changes=[];projected=[]
    for row,meta_path,meta,source,native,evidence,changed in checked:
        new=dict(row)
        if changed:
            directory=output/row['slug'];directory.mkdir()
            os.link(source,directory/'app.spk')
            screenshots=meta_path.parent/'screenshots'
            if screenshots.exists():
                files=list(screenshots.rglob('*'))
                if any(p.is_symlink() for p in files) or sum(p.stat().st_size for p in files if p.is_file())>256*1024*1024:
                    raise ValueError('screenshots must be bounded regular public assets')
                shutil.copytree(screenshots,directory/'screenshots')
            meta.update(version=native['version'],versionNumber=native['versionNumber'],
                        developmentNativeVersionEvidenceSha256=digest(evidence))
            with (directory/'metadata.json').open('x') as stream:json.dump(meta,stream,indent=2);stream.write('\n')
            new.update(metadata=str(directory/'metadata.json'),spk=str(directory/'app.spk'),
                       version=native['version'],versionNumber=native['versionNumber'])
            changes.append({'slug':row['slug'],'packageId':row['packageId'],'fromVersion':row['version'],
                            'version':native['version'],'versionNumber':native['versionNumber'],'evidenceSha256':digest(evidence)})
        projected.append(new)
    result={**manifest,'at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'selected':projected,
            'nativeVersionsReconciled':True,'nativeVersionChanges':changes,'runtimeVerified':False}
    with (output/'source-manifest.json').open('x') as stream:json.dump(result,stream,indent=2);stream.write('\n')
    return {'output':str(output),'members':35,'changed':changes,'packageIdentitiesChanged':False,'runtimeTouched':False}

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--manifest',type=pathlib.Path,required=True);parser.add_argument('--audit',type=pathlib.Path,required=True);parser.add_argument('--output',type=pathlib.Path,required=True);args=parser.parse_args()
    if not args.output.is_absolute():raise ValueError('new absolute output required')
    print(json.dumps(reconcile(args.manifest,args.audit,args.output)))
