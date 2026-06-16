package io.github.gabrielbbaldez.springtaint.benchmark.bean;

/** A plain form/command bean — the kind of value object request data is bound into. */
public class SearchForm {

    private String term;

    public String getTerm() {
        return term;
    }

    public void setTerm(String term) {
        this.term = term;
    }
}
