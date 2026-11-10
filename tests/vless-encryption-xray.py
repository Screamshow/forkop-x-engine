import json, os, pathlib, socket, subprocess, threading, time, hashlib
import argparse

def main():
    parser=argparse.ArgumentParser(description='Independent Xray VLESS Encryption client interoperability (loopback only).')
    parser.add_argument('--xray',required=True,type=pathlib.Path)
    parser.add_argument('--client',required=True,type=pathlib.Path)
    parser.add_argument('--work',required=True,type=pathlib.Path)
    parser.add_argument('--vision',action='store_true')
    parser.add_argument('--reality',action='store_true')
    parser.add_argument('--plain',action='store_true')
    parser.add_argument('--fingerprint',default='chrome')
    parser.add_argument('--udp',action='store_true')
    args=parser.parse_args()
    os.umask(0o077)
    BASE=pathlib.Path(__file__).resolve().parent.parent
    WORK=args.work.resolve()
    WORK.mkdir(exist_ok=True)
    XRAY=args.xray.resolve()
    CLIENT=args.client.resolve()
    (WORK/'metadata.json').write_text(json.dumps({
        'xray_version':subprocess.check_output([str(XRAY),'version'],text=True),
        'xray_sha256':hashlib.sha256(XRAY.read_bytes()).hexdigest(),
        'client_sha256':hashlib.sha256(CLIENT.read_bytes()).hexdigest(),
        'tls_verification':'enabled; locally generated trust anchor; localhost SAN',
    },indent=2))
    UUID='b831381d-6324-4d53-ad4f-8cda48b30811'
    def port():
        with socket.socket() as s: s.bind(('127.0.0.1',0)); return s.getsockname()[1]
    def wait(p,proc):
        for _ in range(100):
            if proc.poll() is not None: raise RuntimeError('process exited')
            try:
                with socket.create_connection(('127.0.0.1',p),.1): return
            except OSError: time.sleep(.05)
        raise RuntimeError('listener not ready')
    def exact(s,n):
        b=b''
        while len(b)<n:
            c=s.recv(n-len(b))
            if not c: raise RuntimeError('early EOF')
            b+=c
        return b
    def socks(p,target):
        s=socket.create_connection(('127.0.0.1',p),10); s.settimeout(20)
        s.sendall(b'\x05\x01\x00'); assert exact(s,2)==b'\x05\x00'
        s.sendall(b'\x05\x01\x00\x01\x7f\x00\x00\x01'+target.to_bytes(2,'big'))
        h=exact(s,4); assert h[1]==0,h
        exact(s,{1:4,4:16}[h[3]]+2)
        return s
    def echo_conn(c):
        with c:
            while True:
                b=c.recv(65536)
                if not b: return
                c.sendall(b)
    sink=socket.socket(); sink.bind(('127.0.0.1',0)); sink.listen()
    def echo():
        while True:
            c,_=sink.accept(); threading.Thread(target=echo_conn,args=(c,),daemon=True).start()
    threading.Thread(target=echo,daemon=True).start()
    udp_sink=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    udp_sink.bind(('127.0.0.1',0))
    def udp_echo():
        while True:
            data,address=udp_sink.recvfrom(65535)
            udp_sink.sendto(data,address)
    threading.Thread(target=udp_echo,daemon=True).start()
    def udp_probe(proxy):
        with socket.create_connection(('127.0.0.1',proxy),10) as control:
            control.settimeout(10)
            control.sendall(b'\x05\x01\x00'); assert exact(control,2)==b'\x05\x00'
            control.sendall(b'\x05\x03\x00\x01'+b'\x00'*6)
            header=exact(control,4); assert header[1]==0 and header[3]==1,header
            address=socket.inet_ntoa(exact(control,4)); relay_port=int.from_bytes(exact(control,2),'big')
            if address=='0.0.0.0': address='127.0.0.1'
            with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as udp:
                udp.settimeout(10)
                for size in (17,1300,4096):
                    payload=os.urandom(size)
                    frame=b'\x00\x00\x00\x01\x7f\x00\x00\x01'+udp_sink.getsockname()[1].to_bytes(2,'big')+payload
                    udp.sendto(frame,(address,relay_port))
                    received,_=udp.recvfrom(65535)
                    assert received==frame, 'UDP echo mismatch'
    subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(WORK/'key.pem'),'-out',str(WORK/'cert.pem'),'-days','2','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost','-addext','basicConstraints=critical,CA:FALSE'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    import ssl
    sslctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    sslctx.set_alpn_protocols(['h2','http/1.1'])
    sslctx.load_cert_chain(str(WORK/'cert.pem'),str(WORK/'key.pem'))
    sslsink=socket.socket(); sslsink.bind(('127.0.0.1',0)); sslsink.listen()
    def ssl_echo(c):
        try: echo_conn(sslctx.wrap_socket(c,server_side=True))
        except Exception as e: print('TLS-SERVER',str(e),flush=True)
    def ssl_accept():
        while True:
            c,_=sslsink.accept(); threading.Thread(target=ssl_echo,args=(c,),daemon=True).start()
    threading.Thread(target=ssl_accept,daemon=True).start()
    keys=subprocess.check_output([str(XRAY),'x25519'],text=True)
    keys=dict(line.split(': ',1) for line in keys.strip().splitlines())
    private=keys['PrivateKey']; public=keys['Password (PublicKey)']
    results=[]
    for appearance in (['none'] if args.plain else ['native','xorpub','random']):
     for rtt in (['1rtt'] if args.plain else ['1rtt','0rtt']):
      for mode in ['tcp','packet-up','stream-up','stream-one']:
        controls=[]
        remote,local=port(),port(); label=f'{appearance}-{rtt}-{mode}'
        stream={'network':'tcp','security':'tls','tlsSettings':{'alpn':['h2','http/1.1'],'certificates':[{'certificateFile':str(WORK/'cert.pem'),'keyFile':str(WORK/'key.pem')}]}}
        if mode!='tcp': stream.update(network='xhttp',xhttpSettings={'path':'/api/events','mode':mode,'extra':{'xPaddingBytes':'100-120'}})
        server={'log':{'loglevel':'debug'},'inbounds':[{'listen':'127.0.0.1','port':remote,'protocol':'vless','settings':{'clients':[{'id':UUID}],'decryption':f'mlkem768x25519plus.{appearance}.600s.{private}'},'streamSettings':stream}],'outbounds':[{'protocol':'freedom','settings':{'finalRules':[{'action':'allow'}]}}]}
        outbound={'type':'vless','tag':'v','server':'127.0.0.1','server_port':remote,'uuid':UUID,'encryption':f'mlkem768x25519plus.{appearance}.{rtt}.{public}','tls':{'enabled':True,'server_name':'localhost','certificate_path':str(WORK/'cert.pem'),'alpn':['h2'] if mode!='tcp' else ['http/1.1'],'utls':{'enabled':True,'fingerprint':'chrome'}}}
        if mode!='tcp': outbound['transport']={'type':'xhttp','path':'/api/events','mode':mode,'x_padding_bytes':'100-120'}
        if args.vision:
            outbound['flow']='xtls-rprx-vision'
            server['inbounds'][0]['settings']['clients'][0]['flow']='xtls-rprx-vision'
        if args.reality:
            stream.pop('tlsSettings')
            stream.update(security='reality',realitySettings={'dest':'127.0.0.1:'+str(sslsink.getsockname()[1]),'serverNames':['localhost'],'privateKey':private,'shortIds':['0123456789abcdef']})
            outbound['tls'].pop('certificate_path')
            outbound['tls']['reality']={'enabled':True,'public_key':public,'short_id':'0123456789abcdef'}
        outbound['tls']['utls']['fingerprint']=args.fingerprint
        if args.plain:
            outbound['encryption']='none'
            server['inbounds'][0]['settings']['decryption']='none'
            if args.vision and mode!='tcp':
                # Xray supports Vision over XHTTP only with Encryption.
                continue
        client={'log':{'level':'debug'},'inbounds':[{'type':'socks','tag':'in','listen':'127.0.0.1','listen_port':local}],'outbounds':[outbound],'route':{'final':'v'}}
        sp=WORK/(label+'-server.json'); cp=WORK/(label+'-client.json'); sp.write_text(json.dumps(server)); cp.write_text(json.dumps(client))
        procs=[]
        try:
          for exe,config,p in [(XRAY,sp,remote),(CLIENT,cp,local)]:
            log=open(WORK/(label+('-xray.log' if exe==XRAY else '-xrust.log')),'w')
            procs.append(subprocess.Popen([str(exe),'run','-c',str(config)],stdout=log,stderr=log)); wait(p,procs[-1])
          for repeat in range(3):
            with socks(local,sink.getsockname()[1]) as s:
              payload=os.urandom(256*1024+37)
              sender=threading.Thread(target=s.sendall,args=(payload,)); sender.start()
              received=exact(s,len(payload)); sender.join(); assert received==payload
          tlsclient=ssl.create_default_context(cafile=str(WORK/'cert.pem'))
          with tlsclient.wrap_socket(socks(local,sslsink.getsockname()[1]),server_hostname='localhost') as s:
            payload=os.urandom(65573)
            s.sendall(payload); assert exact(s,len(payload))==payload
          print('PASS inner-TLS',label,flush=True)
          if args.udp:
            udp_probe(local); print('PASS UDP',label,flush=True)
          if appearance=='native' and rtt=='0rtt' and mode=='packet-up':
            procs[0].terminate(); procs[0].wait(5)
            log=open(WORK/(label+'-xray-restarted.log'),'w')
            procs[0]=subprocess.Popen([str(XRAY),'run','-c',str(sp)],stdout=log,stderr=log); wait(remote,procs[0])
            rejected=False
            try:
              with socks(local,sink.getsockname()[1]) as s:
                s.sendall(b'expired ticket'); exact(s,14)
            except (OSError, RuntimeError, AssertionError): rejected=True
            assert rejected, 'server restart must reject old ticket'
            with socks(local,sink.getsockname()[1]) as s:
              s.sendall(b'fresh handshake'); assert exact(s,15)==b'fresh handshake'
            controls.append('expired-ticket-recovery'); print('PASS expired-ticket-recovery',flush=True)
          if (appearance=='native' or args.plain) and rtt=='1rtt' and mode==('tcp' if args.plain else 'packet-up'):
            import copy
            for negative in ['wrong-sni','wrong-key','wrong-uuid']:
              bad=copy.deepcopy(client)
              if negative=='wrong-sni': bad['outbounds'][0]['tls']['server_name']='wrong.example'
              elif negative=='wrong-key':
                other=dict(line.split(': ',1) for line in subprocess.check_output([str(XRAY),'x25519'],text=True).strip().splitlines())
                if args.reality:
                    bad['outbounds'][0]['tls']['reality']['public_key']=other['Password (PublicKey)']
                elif not args.plain:
                    bad['outbounds'][0]['encryption']='mlkem768x25519plus.native.1rtt.'+other['Password (PublicKey)']
                else:
                    continue
              else: bad['outbounds'][0]['uuid']='11111111-1111-4111-8111-111111111111'
              procs[1].terminate(); procs[1].wait(5); cp.write_text(json.dumps(bad))
              log=open(WORK/(negative+'-xrust.log'),'w')
              procs[1]=subprocess.Popen([str(CLIENT),'run','-c',str(cp)],stdout=log,stderr=log); wait(local,procs[1])
              rejected=False
              try:
                with socks(local,sink.getsockname()[1]) as s:
                  s.sendall(b'must fail'); exact(s,9)
              except (OSError, RuntimeError, AssertionError): rejected=True
              assert rejected, negative+' unexpectedly passed'
              controls.append(negative); print('PASS',negative,flush=True)
          results.append({'case':label,'success':True,'transfers':3,'udp_packets':3 if args.udp else 0,'controls':controls}); print('PASS',label,flush=True)
        except Exception as e:
          results.append({'case':label,'success':False,'error':str(e)}); print('FAIL',label,str(e),flush=True)
        finally:
          for proc in procs:
            proc.terminate()
            try: proc.wait(5)
            except subprocess.TimeoutExpired: proc.kill(); proc.wait()
        (WORK/'results.json').write_text(json.dumps(results,indent=2))
    assert all(r['success'] for r in results), 'interop failures'

if __name__ == "__main__":
    main()
