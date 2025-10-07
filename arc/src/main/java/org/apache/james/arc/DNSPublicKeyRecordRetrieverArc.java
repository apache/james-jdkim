package org.apache.james.arc;

import org.apache.james.arc.exceptions.ArcException;
import org.apache.james.jdkim.impl.DNSPublicKeyRecordRetriever;
import org.apache.james.jspf.impl.DefaultSPF;
import org.apache.james.jspf.impl.SPF;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import java.util.Hashtable;

public class DNSPublicKeyRecordRetrieverArc extends DNSPublicKeyRecordRetriever implements PublicKeyRetrieverArc {
    public static final String JAVA_NAMING_FACTORY_INITIAL = "java.naming.factory.initial";
    public static final String COM_SUN_JNDI_DNS_DNS_CONTEXT_FACTORY = "com.sun.jndi.dns.DnsContextFactory";
    public static final String TXT = "TXT";

    public DNSPublicKeyRecordRetrieverArc() {
        super();
    }

    @Override
    public String getSpfRecord(String helo, String from, String ip) {
        Thread.currentThread().setContextClassLoader(getClass().getClassLoader());
        SPF spf = new DefaultSPF();
        return spf.checkSPF(ip, from, helo).getHeaderText();
    }

    @Override
    public String getDmarcRecord(String dnsLabel) {
        Hashtable<String, String> env = new Hashtable<>();
        env.put(JAVA_NAMING_FACTORY_INITIAL, COM_SUN_JNDI_DNS_DNS_CONTEXT_FACTORY);
        DirContext ctx;
        dnsLabel = "_dmarc." + dnsLabel;
        try {
            ctx = new InitialDirContext(env);
        } catch (NamingException e) {
            throw new ArcException(String.format("Naming error when creating InitialDirContext using [%s]", dnsLabel), e);
        }

        Attributes attrs;
        try {
            attrs = ctx.getAttributes(dnsLabel, new String[]{TXT});
        } catch (NamingException e) {
            throw new ArcException(String.format("Naming error when getting attributes using [%s]", dnsLabel), e);
        }

        Attribute txtAttr = attrs.get(TXT);
        try {
            if (txtAttr != null) {
                StringBuilder sb = new StringBuilder();
                NamingEnumeration<?> e = txtAttr.getAll();
                while (e.hasMore()) {
                    sb.append(e.next().toString().replace("\"", ""));
                }
                return sb.toString();
            }
        } catch (NamingException e) {
            throw new ArcException(String.format("Naming error when looping through attributes using [%s]", dnsLabel), e);
        }
        return null;
    }
}
