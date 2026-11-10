#!/usr/bin/env python3
"""Verify GitHub release assets, sign APKs locally and publish mirror-only URLs."""
import argparse,fcntl,hashlib,json,os,re,shutil,subprocess,tempfile,urllib.request
from pathlib import Path
REPOSITORY='Screamshow/forkop-x-engine'
MIRROR_BASE='https://mirror.51343.ru/forkop/sing-box-x'
def fetch(url):
    req=urllib.request.Request(url,headers={'User-Agent':'sing-box-x-mirror','Accept':'application/vnd.github+json' if url.startswith('https://api.github.com/') else 'application/octet-stream'})
    with urllib.request.urlopen(req,timeout=120) as response:return response.read()
def digest(data):return hashlib.sha256(data).hexdigest()
def publish_catalog(root, published, release, tag):
    catalog={**published,'manifest_url':f'{MIRROR_BASE}/releases/{tag}/manifest.json',
             'prerelease':bool(release['prerelease']),
             'status':'candidate' if release['prerelease'] else 'stable'}
    index='candidate.json' if release['prerelease'] else 'latest.json'
    temporary=root/(index+'.new');temporary.write_text(json.dumps(catalog,indent=2)+'\n')
    temporary.chmod(0o644);os.replace(temporary,root/index)
    candidate=root/'candidate.json'
    if not release['prerelease'] and candidate.exists():
        previous=json.loads(candidate.read_text())
        if previous.get('release_tag',previous.get('version'))==tag:
            candidate.unlink()
    return index

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tag',required=True)
    parser.add_argument('--root',type=Path,default=Path('/srv/mirror/public/forkop/sing-box-x'))
    parser.add_argument('--apk-tool',default='/root/.cache/forkop/openwrt-sdk/extracted/apk/staging_dir/host/bin/apk')
    parser.add_argument('--sign-key',default='/srv/mirror/keys/forkop-apk.pem')
    parser.add_argument('--public-key',default='/srv/mirror/public/forkop/forkop-apk.pem')
    args=parser.parse_args()
    if not re.fullmatch(r'\d+\.\d+\.\d+(-r[1-9]\d*)?',args.tag):raise ValueError('Invalid tag')
    args.root.mkdir(parents=True,exist_ok=True)
    with (args.root/'.sync.lock').open('w') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        release=json.loads(fetch(f'https://api.github.com/repos/{REPOSITORY}/releases/tags/{args.tag}'))
        if release['draft'] or release['tag_name']!=args.tag:raise ValueError('Unexpected release')
        assets={a['name']:a for a in release['assets']}
        manifest_data=fetch(assets['manifest.json']['browser_download_url'])
        if digest(manifest_data)!=assets['manifest.json']['digest'].removeprefix('sha256:'):raise ValueError('Manifest digest mismatch')
        manifest=json.loads(manifest_data)
        if manifest.get('release_tag',manifest['version'])!=args.tag or manifest['name']!='sing-box-x':raise ValueError('Unexpected manifest')
        revision=str(manifest.get('package_revision',args.tag.rsplit('-r',1)[1] if '-r' in args.tag else '1'))
        if not re.fullmatch(r'[1-9]\d*',revision):raise ValueError('Invalid package revision')
        required={f'sing-box-x_{manifest["version"]}-{rev}_{arch}.{fmt}' for arch in ('aarch64_cortex-a53','x86_64') for fmt,rev in (('apk','r'+revision),('ipk',revision))}
        if not required.issubset({a['name'] for a in manifest['assets']}):raise ValueError('Required packages missing')
        releases=args.root/'releases';releases.mkdir(exist_ok=True);destination=releases/args.tag
        if destination.exists():
            saved=json.loads((destination/'upstream-manifest.json').read_text())
            if saved!=manifest:raise ValueError('Refusing to replace existing release with changed upstream content')
            published=json.loads((destination/'manifest.json').read_text())
            for asset in published['assets']:
                if digest((destination/asset['name']).read_bytes())!=asset['sha256']:raise ValueError('Existing mirror asset corrupt')
            index=publish_catalog(args.root,published,release,args.tag)
            print(f'{args.tag} already verified; {index} refreshed');return
        staging=Path(tempfile.mkdtemp(prefix=f'.{args.tag}-',dir=releases))
        try:
            (staging/'upstream-manifest.json').write_bytes(manifest_data)
            for asset in manifest['assets']:
                name=asset['name']
                if name!=Path(name).name or not re.fullmatch(r'[a-zA-Z0-9_.-]+',name):raise ValueError('Unsafe asset name')
                original=fetch(assets[name]['browser_download_url'])
                gh_digest=assets[name]['digest']
                if gh_digest!='sha256:'+asset['sha256'] or digest(original)!=asset['sha256'] or len(original)!=asset['size']:raise ValueError(f'Invalid upstream asset: {name}')
                target=staging/name;target.write_bytes(original)
                asset['upstream_sha256']=asset['sha256']
                if target.suffix=='.apk':
                    with tempfile.TemporaryDirectory(prefix='sing-box-x-keys-') as keys:
                        shutil.copyfile(args.public_key,Path(keys)/'forkop-apk.pem')
                        if not asset.get('signed'):
                            subprocess.run([args.apk_tool,'adbsign','--allow-untrusted','--sign-key',args.sign_key,str(target)],check=True)
                        subprocess.run([args.apk_tool,'--keys-dir',keys,'verify',str(target)],check=True)
                    dump=subprocess.check_output([args.apk_tool,'adbdump','--allow-untrusted',str(target)],text=True)
                    size=re.search(r'installed-size:\s*(\d+)',dump)
                    if not size or int(size.group(1))!=asset['installed_size']:raise ValueError('Signing changed installed size')
                    asset['signed']=True
                asset['sha256']=digest(target.read_bytes());asset['size']=target.stat().st_size
                asset['url']=f'{MIRROR_BASE}/releases/{args.tag}/{name}'
            manifest['prerelease']=bool(release['prerelease'])
            (staging/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
            (staging/'SHA256SUMS').write_text(''.join(digest(p.read_bytes())+'  '+p.name+'\n' for p in sorted(staging.iterdir()) if p.is_file()))
            for p in staging.iterdir():p.chmod(0o644)
            staging.chmod(0o755);os.rename(staging,destination)
            index=publish_catalog(args.root,manifest,release,args.tag)
            print(f'Published {args.tag}: {len(manifest["assets"])} verified assets; {index}')
        except BaseException:
            if staging.exists():shutil.rmtree(staging)
            raise
if __name__=='__main__':main()
