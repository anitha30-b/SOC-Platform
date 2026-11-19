"""Legacy ownership resolution and global-origin detection boundary fixtures."""
import unittest

import detection_scope_regression as support
import models
import detection_engine as detection


class LegacyScopeTests(unittest.TestCase):
    setUp = support.DetectionScopeTests.setUp
    tearDown = support.DetectionScopeTests.tearDown
    event = support.DetectionScopeTests.event
    correlation_rule = support.DetectionScopeTests.correlation_rule

    def assessment(self, aid, uid):
        self.db.add(models.Assessment(id=aid, user_id=uid, target='https://example.invalid'))
        self.db.flush()

    def source(self, sid, uid, client=None):
        self.db.add(models.TelemetrySource(
            id=sid, name=f'fixture-source-{sid}', token_hash=f'unused-fixture-{sid}',
            owner_user_id=uid, client_id=client, created_by=uid, enabled=True,
        ))
        self.db.flush()

    def legacy_event(self, assessment=None, source=None):
        row = self.event(owner=None)
        row.assessment_id = assessment
        row.telemetry_source_id = source
        self.db.flush()
        return row

    def test_legacy_assessments_join_their_personal_owner(self):
        self.assessment(101, 1)
        self.legacy_event(assessment=101)
        self.legacy_event(assessment=101)
        self.assertTrue(detection.threshold_reached(self.db, self.event(owner=1), 3, 5))

    def test_legacy_assessments_do_not_join_another_owner(self):
        self.assessment(102, 2)
        self.legacy_event(assessment=102)
        self.legacy_event(assessment=102)
        self.assertFalse(detection.threshold_reached(self.db, self.event(owner=1), 3, 5))

    def test_legacy_assessments_share_within_the_client(self):
        self.assessment(110, 10)
        self.assessment(111, 11)
        self.legacy_event(assessment=110)
        self.legacy_event(assessment=111)
        self.assertTrue(detection.threshold_reached(self.db, self.event(owner=10, client=100), 3, 5))

    def test_current_legacy_assessment_resolves_owner(self):
        self.assessment(101, 1)
        self.event(owner=1)
        self.event(owner=1)
        current = self.legacy_event(assessment=101)
        self.assertTrue(detection.threshold_reached(self.db, current, 3, 5))

    def test_legacy_source_joins_its_personal_owner(self):
        self.source(201, 1)
        self.legacy_event(source=201)
        self.legacy_event(source=201)
        self.assertTrue(detection.threshold_reached(self.db, self.event(owner=1), 3, 5))

    def test_legacy_source_does_not_join_another_owner(self):
        self.source(202, 2)
        self.legacy_event(source=202)
        self.legacy_event(source=202)
        self.assertFalse(detection.threshold_reached(self.db, self.event(owner=1), 3, 5))

    def test_current_legacy_source_resolves_client(self):
        self.source(210, 10, client=100)
        self.event(owner=10, client=100)
        self.event(owner=11, client=100)
        current = self.legacy_event(source=210)
        self.assertTrue(detection.threshold_reached(self.db, current, 3, 5))

    def test_explicit_client_wins_over_legacy_assessment(self):
        self.assessment(101, 1)
        for _ in range(2):
            row = self.event(owner=None, client=200)
            row.assessment_id = 101
        self.db.flush()
        self.assertFalse(detection.threshold_reached(self.db, self.event(owner=1), 3, 5))

    def test_assessment_precedes_source_when_both_legacy_links_exist(self):
        self.assessment(102, 2)
        self.source(201, 1)
        self.legacy_event(assessment=102, source=201)
        self.legacy_event(assessment=102, source=201)
        self.assertFalse(detection.threshold_reached(self.db, self.event(owner=1), 3, 5))

    def test_orphan_links_do_not_contribute_to_global_counts(self):
        self.legacy_event(assessment=999)
        self.legacy_event(source=999)
        current = self.event(owner=None)
        self.assertFalse(detection.threshold_reached(self.db, current, 3, 5))

    def test_current_orphan_does_not_fall_back_to_global_scope(self):
        self.event(owner=None)
        self.event(owner=None)
        current = self.legacy_event(assessment=999)
        self.assertFalse(detection.threshold_reached(self.db, current, 3, 5))

    def test_same_client_correlation_still_works_across_users(self):
        self.event(owner=11, client=100)
        current = self.event(owner=10, client=100, kind='LOGIN_SUCCESS')
        self.assertTrue(detection.correlation_reached(self.db, current, self.correlation_rule()))


if __name__ == '__main__':
    unittest.main(verbosity=2)
