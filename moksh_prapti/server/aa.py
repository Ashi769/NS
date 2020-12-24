from M2Crypto import BIO, SMIME, X509
    import smtplib, string, sys
    
    def sendsmime(from_addr, to_addrs, subject, msg, from_key, from_cert=None, to_certs=None, smtpd='localhost'):
    
        msg_bio = BIO.MemoryBuffer(msg)
        sign = from_key
        encrypt = to_certs
    
        s = SMIME.SMIME()
        if sign:
            s.load_key(from_key, from_cert)
            p7 = s.sign(msg_bio, flags=SMIME.PKCS7_TEXT)
            msg_bio = BIO.MemoryBuffer(msg) # Recreate coz sign() has consumed it.
    
        if encrypt:
            sk = X509.X509_Stack()
            for x in to_certs:
                sk.push(X509.load_cert(x))
            s.set_x509_stack(sk)
            s.set_cipher(SMIME.Cipher('des_ede3_cbc'))
            tmp_bio = BIO.MemoryBuffer()
            if sign:
                s.write(tmp_bio, p7)
            else:
                tmp_bio.write(msg)
            p7 = s.encrypt(tmp_bio)
    
        out = BIO.MemoryBuffer()
        out.write('From: %s\r\n' % from_addr)
        out.write('To: %s\r\n' % string.join(to_addrs, ", "))
        out.write('Subject: %s\r\n' % subject) 
        if encrypt:
            s.write(out, p7)
        else:
            if sign:
                s.write(out, p7, msg_bio, SMIME.PKCS7_TEXT)
            else:
                out.write('\r\n')
                out.write(msg)
        out.close()
    
        smtp = smtplib.SMTP()
        smtp.connect(smtpd)
        smtp.sendmail(from_addr, to_addrs, out.read())
        smtp.quit()
