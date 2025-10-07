package org.apache.james.arc;

import org.apache.james.jdkim.api.PublicKeyRecordRetriever;

public interface PublicKeyRetrieverArc extends PublicKeyRecordRetriever {

    String getDmarcRecord(String query);

    String getSpfRecord(String helo, String from, String ip);
}
