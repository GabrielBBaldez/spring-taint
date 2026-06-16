package io.github.gabrielbbaldez.springtaint.benchmark.xxe;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.w3c.dom.Document;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

/**
 * XXE: a user-controlled URI is handed to a default (unhardened) DocumentBuilder.
 * External entities in the referenced document can read local files
 * ({@code file:///etc/passwd}) or make server-side requests.
 *
 * <p>EXPECTED: xxe (CWE-611). The first version reports any external input
 * reaching {@code parse}; hardening of the builder is not yet analysed.
 */
@RestController
public class XxeController {

    @GetMapping("/xml/parse")
    public String parse(@RequestParam String uri) throws Exception {                 // taint-source: @RequestParam uri
        DocumentBuilder builder = DocumentBuilderFactory.newInstance().newDocumentBuilder();
        Document doc = builder.parse(uri);                                           // taint-sink: DocumentBuilder.parse -> EXPECTED xxe
        return doc.getDocumentElement().getNodeName();
    }
}
