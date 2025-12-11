from openstack.connection import Connection
from src.utility.logging import get_logger

logger = get_logger()

NUM_PERMANENT_SUBNETS = 1
NUM_PERMANENT_NETS = 2
NUM_PERMANENT_SECURITY_GROUPS = 1

IMAGE_NAME_SUFFIX = "_image"


def get_image_name(host_name: str):
    return host_name + IMAGE_NAME_SUFFIX


class OpenstackImager:
    def __init__(
        self,
        openstack_conn: Connection,
    ):
        self.openstack_conn: Connection = openstack_conn

    def save_all_snapshots(self):
        logger.debug("Saving all snapshots...")
        for instance in self.openstack_conn.list_servers():
            self._save_snapshot(instance)

    def clean_snapshots(self):
        logger.debug("Cleaning all snapshots...")
        images = self.openstack_conn.list_images()
        for image in images:
            if "_image" in image.name:
                self.openstack_conn.delete_image(image.id, wait=True)

    def _save_snapshot(self, host):
        snapshot_name = get_image_name(host.name)
        image = self.openstack_conn.get_image(snapshot_name)
        if image:
            logger.debug(f"Image '{snapshot_name}' already exists. Deleting...")
            self.openstack_conn.delete_image(image.id, wait=True)  # type: ignore

        logger.debug(f"Creating snapshot {snapshot_name} for instance {host.id}...")
        image = self.openstack_conn.create_image_snapshot(
            snapshot_name, host.id, wait=True
        )
        return image.id
