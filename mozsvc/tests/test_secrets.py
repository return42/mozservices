# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.

# pylint: disable=W1505

import unittest
import tempfile
import os
import time
import itertools

from mozsvc.secrets import Secrets, FixedSecrets, DerivedSecrets


class TestSecrets(unittest.TestCase):

    def setUp(self):
        self._files = []

    def tearDown(self):
        for file in self._files:
            if os.path.exists(file):
                os.remove(file)

    def tempfile(self):
        fd, path = tempfile.mkstemp()
        os.close(fd)
        self._files.append(path)
        return path

    def test_read_write(self):
        secrets = Secrets()

        # We can only add one secret per second to the file, since
        # they are timestamped to 1s resolution.  Fake it.
        real_time = time.time

        _i = itertools.count(int(real_time()))
        def _next():
            return next(_i)
        time.time = _next
        try:
            secrets.add(b'phx23456')
            secrets.add(b'phx23456')
            secrets.add(b'phx23')
        finally:
            time.time = real_time

        phx23456_secrets = secrets.get(b'phx23456')
        self.assertEqual(len(secrets.get(b'phx23456')), 2)
        self.assertEqual(len(secrets.get(b'phx23')), 1)

        path = self.tempfile()

        secrets.save(path)

        secrets2 = Secrets(path)
        self.assertTrue(len(secrets2.get(b'phx23456')) == 2)
        self.assertTrue(len(secrets2.get(b'phx23')) == 1)
        self.assertTrue(secrets2.get(b'phx23456') == phx23456_secrets)

    def test_multiple_files(self):
        # creating two distinct files
        secrets = Secrets()
        secrets.add(b'phx23456')
        one = self.tempfile()
        secrets.save(one)

        secrets = Secrets()
        secrets.add(b'phx123')
        two = self.tempfile()
        secrets.save(two)

        # loading the two files
        files = one, two
        secrets = Secrets(files)
        keys = list(secrets.keys())
        keys.sort()
        self.assertEqual(keys, [b'phx123', b'phx23456'])

    def test_fixed_secrets(self):
        secrets = FixedSecrets(['one', 'two'])
        self.assertTrue(secrets.get(b'phx123') == ['one', 'two'])
        self.assertTrue(secrets.get(b'phx234') == ['one', 'two'])

    def test_derived_secrets(self):
        master_secrets = [b'abcdef', b'1234567890']
        secrets = DerivedSecrets(master_secrets)
        derived1 = secrets.get(b'phx123')
        derived2 = secrets.get(b'phx987')
        # Secrets for the same node should derived consistently.
        self.assertEquals(derived1, secrets.get(b'phx123'))
        self.assertEquals(derived2, secrets.get(b'phx987'))
        # Secrets for different nodes should be different.
        self.assertEquals(set(derived1).intersection(derived2), set())
        # Length of derived secret mathches length of master secret.
        for derived in (derived1, derived2):
            self.assertEquals(len(derived), len(master_secrets))
            for d, m in zip(derived, master_secrets):
                self.assertEquals(len(d), len(m))
