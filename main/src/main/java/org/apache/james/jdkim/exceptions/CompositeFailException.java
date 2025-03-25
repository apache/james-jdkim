package org.apache.james.jdkim.exceptions;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class CompositeFailException extends FailException {
    private final List<FailException> exceptions = new ArrayList<>();

    public CompositeFailException(Collection<FailException> exceptions, String message) {
        super(message);
        this.exceptions.addAll(exceptions);
    }

    public List<FailException> getExceptions() {
        return exceptions;
    }
}
