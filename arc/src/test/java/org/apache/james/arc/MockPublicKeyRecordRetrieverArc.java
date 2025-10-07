package org.apache.james.arc;

import org.apache.james.arc.exceptions.ArcException;
import org.apache.james.jdkim.MockPublicKeyRecordRetriever;
import org.apache.james.jdkim.exceptions.PermFailException;
import org.apache.james.jdkim.exceptions.TempFailException;

import java.util.List;

public class MockPublicKeyRecordRetrieverArc extends MockPublicKeyRecordRetriever implements PublicKeyRetrieverArc {

    public static final String DMARC = "_dmarc.";
    public static final String SPF = "_spf.";
    public static class SpfRecord extends  MockPublicKeyRecordRetriever.Record {

        public SpfRecord(String helo, String from, String ip, String spfRecord) {
            super(SPF, ip + helo + from, spfRecord);
        }

        public static SpfRecord spfOf(String helo, String from, String ip, String spfRecord) {
            return new SpfRecord(helo, from, ip, spfRecord);
        }
    }

    public static class DmarcRecord extends  MockPublicKeyRecordRetriever.Record {

        public DmarcRecord(String selector, String domain, String dmarcRecord) {
            super(DMARC, domain, dmarcRecord);
        }

        public static DmarcRecord dmarcOf(String selector, String domain, String dmarcRecord) {
            return new DmarcRecord(selector, domain, dmarcRecord);
        }
    }

    public MockPublicKeyRecordRetrieverArc(Record... records) {
        super(records);
    }

    @Override
    public String getSpfRecord(String helo, String from, String ip) {
        try {
           String token = ip + helo + from;
                List<String> recs = super.getRecords("dns/txt", SPF,token);
                if (recs.isEmpty()) {
                    return null;
                }
                return recs.get(0); //TODO: multiple records?
        } catch (TempFailException e) {
            throw new ArcException("Temporary failure looking up DMARC record", e);
        } catch (PermFailException e) {
            throw new ArcException("Permanent failure looking up DMARC record", e);
        }
    }

    @Override
    public String getDmarcRecord(String searchKey){
        try {
                List<String> recs = super.getRecords("dns/txt", DMARC,searchKey);
                if (recs.isEmpty()) {
                    return null;
                }
                return recs.get(0); //TODO: multiple records?
        } catch (TempFailException e) {
            throw new ArcException("Temporary failure looking up DMARC record", e);
        } catch (PermFailException e) {
            throw new ArcException("Permanent failure looking up DMARC record", e);
        }
    }
}
