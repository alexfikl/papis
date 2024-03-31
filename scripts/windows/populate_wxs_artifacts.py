"""Add all components (files) and directories generated by pyinstaller in
dist/papis/_internal into the XML manifest that is used to create the MSI."""

import os
import lxml.etree as et
import uuid


def get_id(*path_components: str) -> str:
    """Create an element ID based on the WiX constraints: 72 chars or less, a-zA-Z_-, starting with underscore or letter.
    Here we use the hash (int) of the path, removing the negative symbol, and prefixed by underscore
    For details, search "Identifier" in
    https://github.com/wixtoolset/wix/blob/2b6fa3ab686188cfe983abbc3d51d1542069b2c8/src/api/wix/WixToolset.Data/ErrorMessages.cs#L966
    """
    path = os.path.join(*path_components)
    result = f"_{abs(hash(path))}"
    return result


wxs_tree = et.parse(".\\scripts\\windows\\papis_template.wxs")
wxs_root = wxs_tree.getroot()

xpath_ns = {"main": "http://wixtoolset.org/schemas/v4/wxs"}
component = wxs_root.xpath(
    ".//main:Directory[@Id='INSTALLFOLDER']", namespaces=xpath_ns
)[0]
package = wxs_root.xpath(".//main:Package", namespaces=xpath_ns)[0]

root_dir = "dist\\papis\\_internal"

directories = et.SubElement(
    component, "Directory", Name="_internal", Id=get_id(root_dir)
)
component_group = et.SubElement(package, "ComponentGroup", Id="_internal")

for root, dirs, files in os.walk(root_dir):
    for dir in dirs:
        relpath = os.path.relpath(root, root_dir)
        parent_path = os.path.dirname(relpath)
        if parent_path == "":
            parent_element = directories
        else:
            parent_element_id = get_id(root_dir, parent_path)
            xpath = f".//Directory[@Id='{parent_element_id}']"
            parent_element = directories.xpath(xpath)[0]

        et.SubElement(parent_element, "Directory", Name=dir, Id=get_id(root, dir))

    if files:
        for index, file in enumerate(files):
            component = et.SubElement(
                component_group,
                "Component",
                Guid=str(uuid.uuid4()),
                Id=f"c{get_id(root, file)}",
                Directory=get_id(root),
            )
            et.SubElement(
                component, "File", KeyPath="yes", Source=os.path.join(root, file)
            )

with open("scripts\\windows\\papis.wxs", mode="wb") as f:
    f.write(et.tostring(wxs_root, pretty_print=True))