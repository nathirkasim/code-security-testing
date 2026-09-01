package com.example.cleanrepo;

import org.w3c.dom.Document;
import org.xml.sax.InputSource;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.StringReader;

public class XmlParserUtil {

    /**
     * Creates a hardened DocumentBuilderFactory with external DTD and entity resolution disabled.
     * Prevents XML External Entity (XXE) attacks (CWE-611).
     */
    public static DocumentBuilderFactory createSecureDocumentBuilderFactory() throws ParserConfigurationException {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        
        // Disallow inline DOCTYPE declarations entirely
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        
        // Disable external entity features
        dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
        dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        
        dbf.setXIncludeAware(false);
        dbf.setExpandEntityReferences(false);
        dbf.setNamespaceAware(true);

        return dbf;
    }

    /**
     * Safely parses XML string using XXE-protected DocumentBuilder.
     */
    public static Document parseSecureXml(String xmlContent) throws Exception {
        if (xmlContent == null || xmlContent.isBlank()) {
            throw new IllegalArgumentException("XML content cannot be null or empty.");
        }

        DocumentBuilderFactory dbf = createSecureDocumentBuilderFactory();
        DocumentBuilder builder = dbf.newDocumentBuilder();
        
        return builder.parse(new InputSource(new StringReader(xmlContent)));
    }
}
