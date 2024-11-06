import ckan.plugins as p
import ckan.plugins.toolkit as toolkit

from ckanext.clamav.utils import scan_file_for_viruses


class ClamavPlugin(p.SingletonPlugin):
    p.implements(p.IConfigurer)
    p.implements(p.IUploader, inherit=True)

    # IConfigurer

    def update_config(self, config_):
        toolkit.add_template_directory(config_, "templates")
        toolkit.add_public_directory(config_, "public")
        toolkit.add_resource("fanstatic", "clamav")

    # IUploader

    def get_resource_uploader(self, data_dict):
        if not data_dict.get("upload"):
            return

        scan_file_for_viruses(data_dict)
