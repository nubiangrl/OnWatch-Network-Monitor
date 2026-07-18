import unittest

from relationship_engine import (
    RelationshipManager,
    RelationshipStore,
    serialize_relationships_for_legacy_projection,
)


class RelationshipMigrationTests(unittest.TestCase):
    def test_legacy_projection_is_built_from_authoritative_relationships(self):
        store = RelationshipStore(config={}, autosave=False)
        manager = RelationshipManager(store)

        manager.create_relationship(
            "Router",
            "Laptop",
            relationship_type="PHYSICAL",
            relationship_state="LIVE",
            confidence=85,
            currently_verified=True,
            active=True,
            source="MANUAL",
            state_details="Test link",
            save=False,
        )

        projection = serialize_relationships_for_legacy_projection(manager)

        self.assertIn("Laptop", projection)
        self.assertEqual(projection["Laptop"]["parent"], "Router")
        self.assertEqual(projection["Laptop"]["relationship"], "Test link")
        self.assertEqual(projection["Laptop"]["source"], "MANUAL")

    def test_legacy_projection_prefers_role_path_over_cdp_physical_link(self):
        store = RelationshipStore(config={}, autosave=False)
        manager = RelationshipManager(store)

        manager.create_relationship(
            "Cox Modem Gateway",
            "Main Switch",
            relationship_type="PHYSICAL",
            relationship_state="CONFIGURED",
            confidence=90,
            currently_verified=False,
            active=True,
            source="auto_infrastructure_link_engine",
            state_details="Configured Infrastructure Role Path",
            metadata={"selection_source": "preferred_role_path"},
            save=False,
        )
        manager.create_relationship(
            "Edge Router",
            "Main Switch",
            relationship_type="PHYSICAL",
            relationship_state="LIVE",
            confidence=100,
            currently_verified=True,
            active=True,
            source="CDP",
            state_details="CDP Discovered Physical Link",
            metadata={"selection_source": "cdp_discovery"},
            save=False,
        )

        projection = serialize_relationships_for_legacy_projection(manager)

        self.assertEqual(projection["Main Switch"]["parent"], "Cox Modem Gateway")
        self.assertEqual(projection["Main Switch"]["selection_source"], "preferred_role_path")
        self.assertEqual(len(manager.list_relationships(child="Main Switch")), 2)

    def test_legacy_projection_selection_is_deterministic_for_reversed_insertion_order(self):
        store = RelationshipStore(config={}, autosave=False)
        manager = RelationshipManager(store)

        manager.create_relationship(
            "Edge Router",
            "Main Switch",
            relationship_type="PHYSICAL",
            relationship_state="LIVE",
            confidence=100,
            currently_verified=True,
            active=True,
            source="CDP",
            state_details="CDP Discovered Physical Link",
            metadata={"selection_source": "cdp_discovery"},
            save=False,
        )
        manager.create_relationship(
            "Cox Modem Gateway",
            "Main Switch",
            relationship_type="PHYSICAL",
            relationship_state="CONFIGURED",
            confidence=90,
            currently_verified=False,
            active=True,
            source="auto_infrastructure_link_engine",
            state_details="Configured Infrastructure Role Path",
            metadata={"selection_source": "preferred_role_path"},
            save=False,
        )

        projection = serialize_relationships_for_legacy_projection(manager)

        self.assertEqual(projection["Main Switch"]["parent"], "Cox Modem Gateway")

    def test_verified_discovery_relationship_is_selected_when_no_role_path_exists(self):
        store = RelationshipStore(config={}, autosave=False)
        manager = RelationshipManager(store)

        manager.create_relationship(
            "Edge Router",
            "Main Switch",
            relationship_type="PHYSICAL",
            relationship_state="LIVE",
            confidence=98,
            currently_verified=True,
            active=True,
            source="LLDP",
            state_details="LLDP Discovered Physical Link",
            metadata={"selection_source": "lldp_discovery"},
            save=False,
        )

        projection = serialize_relationships_for_legacy_projection(manager)

        self.assertEqual(projection["Main Switch"]["parent"], "Edge Router")
        self.assertEqual(projection["Main Switch"]["selection_source"], "lldp_discovery")

    def test_existing_legacy_entries_are_preserved_when_authoritative_candidate_is_lower_priority(self):
        store = RelationshipStore(config={}, autosave=False)
        manager = RelationshipManager(store)

        existing = {
            "Laptop": {
                "parent": "Desk",
                "relationship": "Legacy Entry",
                "source": "legacy",
                "selection_source": "legacy",
                "relationship_type": "PHYSICAL",
                "relationship_state": "CONFIGURED",
                "confidence": 40,
                "currently_verified": False,
                "active": True,
            }
        }

        manager.create_relationship(
            "Router",
            "Laptop",
            relationship_type="PHYSICAL",
            relationship_state="LIVE",
            confidence=60,
            currently_verified=True,
            active=True,
            source="CDP",
            state_details="CDP Discovered Physical Link",
            metadata={"selection_source": "cdp_discovery"},
            save=False,
        )

        projection = serialize_relationships_for_legacy_projection(manager, existing=existing)

        self.assertEqual(projection["Laptop"]["parent"], "Desk")
        self.assertEqual(projection["Laptop"]["source"], "legacy")

    def test_relationship_ids_remain_stable_in_projection(self):
        store = RelationshipStore(config={}, autosave=False)
        manager = RelationshipManager(store)

        relationship = manager.create_relationship(
            "Router",
            "Laptop",
            relationship_type="PHYSICAL",
            relationship_state="LIVE",
            confidence=85,
            currently_verified=True,
            active=True,
            source="MANUAL",
            state_details="Stable relationship",
            relationship_id="rel-stable-123",
            save=False,
        )

        projection = serialize_relationships_for_legacy_projection(manager)

        self.assertEqual(projection["Laptop"]["relationship_id"], relationship.id)
        self.assertEqual(projection["Laptop"]["relationship_id"], "rel-stable-123")


if __name__ == "__main__":
    unittest.main()
