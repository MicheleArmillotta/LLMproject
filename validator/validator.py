from tree_sitter import Language, Parser
import tree_sitter_cpp as tscpp
import re

LANGUAGE = Language(tscpp.language())
parser = Parser(LANGUAGE)

def extract_cpp_identifiers(code: str):
    """
    Estrae identificatori sintattici da codice C++ in modo permissivo:
    - Include nomi qualificati complessi e template
    - Include puntatori e reference
    """
    tree = parser.parse(bytes(code, "utf8"))
    root = tree.root_node
    identifiers = set()

    def get_text(node):
        return code[node.start_byte:node.end_byte].strip()

    def visit(node):
        # nodi più alti possibili che possono contenere tipi complessi
        if node.type in {
            "init_declarator", "parameter_declaration",
            "function_declarator", "function_definition",
            "class_specifier", "namespace_identifier",
            "type_identifier", "template_type",
            "qualified_identifier", "field_expression", "call_expression"
        }:
            identifiers.add(get_text(node))

        for child in node.children:
            visit(child)

    visit(root)
    return identifiers

def normalize_syntax(name: str) -> str:
    """Uniforma punteggiatura -> . per matching sintattico"""
    name = name.replace("::", ".").replace("->", ".")
    # rimuove spazi extra
    name = re.sub(r"\s+", " ", name).strip()
    return name

def check_entities_exist_cpp(code: str, entities: list[str],partial_match):
    identifiers = extract_cpp_identifiers(code)
    normalized_identifiers = set(normalize_syntax(ident) for ident in identifiers)

    result = {}
    for ent in entities:
        ent_norm = normalize_syntax(ent)
        # regex per match di token completo, con punteggiatura ammessa
        pattern = re.compile(rf"(?:^|[\s\.\(\),<>*&]){re.escape(ent_norm)}(?:$|[\s\.\(\),<>*&])")
        found = any(pattern.search(ident) for ident in normalized_identifiers)
        result[ent] = found

    coverage = sum(result.values()) / len(result) if entities else 1.0
    return result, coverage

# === Test ===
if __name__ == "__main__":
    code = """#include "capability.h"
#include "any.h"

void writePackedMessageToFd(int fd, kj::ArrayPtr<const kj::ArrayPtr<const word>> segments) {
  kj::FdOutputStream output(fd);
  writePackedMessage(output, segments);
}

void writeAddressBook(int fd) {
  ::capnp::MallocMessageBuilder message;
  AddressBook::Builder addressBook = message.initRoot<AddressBook>();
  call.header.reset();
}
"""
    entities = [
        "int fd",
        "kj::ArrayPtr<const kj::ArrayPtr<const word>> segments",
        "kj::FdOutputStream output",
        "::capnp::MallocMessageBuilder message",
        "AddressBook::Builder addressBook",
        "header"
    ]
    matches, coverage = check_entities_exist_cpp(code, entities,partial_match = False)
    print("Matches:", matches)
    print("Coverage:", coverage)
