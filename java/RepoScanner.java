import java.io.File;
import java.util.ArrayList;
import java.util.List;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/*
 * Reads direct, explicitly-versioned Maven dependencies from one pom.xml.
 * It only parses XML; it never runs code from the repository.
 */
public final class RepoScanner {
    private static String localName(Node node) {
        String name = node.getLocalName();
        return name == null ? node.getNodeName() : name;
    }

    private static String childText(Element parent, String wanted) {
        NodeList children = parent.getChildNodes();
        for (int i = 0; i < children.getLength(); i++) {
            Node child = children.item(i);
            if (child instanceof Element && wanted.equals(localName(child))) {
                return child.getTextContent().trim();
            }
        }
        return "";
    }

    public static void main(String[] args) {
        if (args.length != 1) {
            System.err.println("Usage: RepoScanner path-to-pom.xml");
            System.exit(2);
        }

        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setNamespaceAware(true);
            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
            factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");

            Document document = factory.newDocumentBuilder().parse(new File(args[0]));
            NodeList containers = document.getElementsByTagNameNS("*", "dependencies");
            List<String> rows = new ArrayList<>();

            for (int i = 0; i < containers.getLength(); i++) {
                Node container = containers.item(i);
                Node parent = container.getParentNode();
                if (!(parent instanceof Element) || !"project".equals(localName(parent))) {
                    continue;
                }

                NodeList children = container.getChildNodes();
                for (int j = 0; j < children.getLength(); j++) {
                    Node child = children.item(j);
                    if (!(child instanceof Element) || !"dependency".equals(localName(child))) {
                        continue;
                    }

                    Element dependency = (Element) child;
                    String group = childText(dependency, "groupId");
                    String artifact = childText(dependency, "artifactId");
                    String version = childText(dependency, "version");

                    // Keep this MVP easy to explain: only literal versions are checked.
                    if (!group.isEmpty() && !artifact.isEmpty()
                            && !version.isEmpty() && !version.contains("$")) {
                        rows.add(group + "\t" + artifact + "\t" + version);
                    }
                }
            }

            for (String row : rows) {
                System.out.println(row);
            }
        } catch (Exception error) {
            System.err.println("Could not read Maven file: " + error.getMessage());
            System.exit(1);
        }
    }
}
