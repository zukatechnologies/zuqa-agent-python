#  BSD 3-Clause License
#
#  Copyright (c) 2019, Elasticsearch BV
#  All rights reserved.
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions are met:
#
#  * Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer.
#
#  * Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
#  * Neither the name of the copyright holder nor the names of its
#    contributors may be used to endorse or promote products derived from
#    this software without specific prior written permission.
#
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
#  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
#  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
#  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
#  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
#  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
#  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
#  CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
#  OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import os
import random
import shutil
import sys
import tempfile

import pytest

from zuqa.conf.constants import ERROR
from zuqa.contrib.zerorpc import Middleware

pytestmark = [
    pytest.mark.zerorpc,
    pytest.mark.skipif(sys.version_info >= (3, 4), reason="zerorpc>=0.4.0,0.5 not python 3 compatible"),
]

zerorpc = pytest.importorskip("zerorpc")
gevent = pytest.importorskip("gevent")


def test_zerorpc_middleware_with_reqrep(elasticapm_client):
    tmpdir = tempfile.mkdtemp()
    server_endpoint = "ipc://{0}".format(os.path.join(tmpdir, "random_zeroserver"))
    try:
        zerorpc.Context.get_instance().register_middleware(Middleware(client=elasticapm_client))
        server = zerorpc.Server(random)
        server.bind(server_endpoint)
        gevent.spawn(server.run)

        client = zerorpc.Client()
        client.connect(server_endpoint)

        with pytest.raises(zerorpc.exceptions.RemoteError) as excinfo:
            client.choice([])

        client.close()
        server.close()
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
    ex = excinfo.value
    assert ex.name == "IndexError"
    assert len(elasticapm_client.events) == 1
    exc = elasticapm_client.events[ERROR][0]["exception"]
    assert exc["type"] == "IndexError"
    frames = exc["stacktrace"]
    assert frames[0]["function"] == "choice"
    assert frames[0]["module"] == "random"
    assert exc["handled"] is False
