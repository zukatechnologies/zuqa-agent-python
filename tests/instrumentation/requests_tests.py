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

import pytest  # isort:skip

pytest.importorskip("requests")  # isort:skip

import requests
from requests.exceptions import InvalidURL, MissingSchema

from zuqa.conf import constants
from zuqa.conf.constants import TRANSACTION
from zuqa.traces import capture_span
from zuqa.utils import compat
from zuqa.utils.disttracing import TraceParent

pytestmark = pytest.mark.requests


def test_requests_instrumentation(instrument, zuqa_client, waiting_httpserver):
    waiting_httpserver.serve_content("")
    url = waiting_httpserver.url + "/hello_world"
    parsed_url = compat.urlparse.urlparse(url)
    zuqa_client.begin_transaction("transaction.test")
    with capture_span("test_request", "test"):
        requests.get(url, allow_redirects=False)
    zuqa_client.end_transaction("MyView")

    transactions = zuqa_client.events[TRANSACTION]
    spans = zuqa_client.spans_for_transaction(transactions[0])
    assert spans[0]["name"].startswith("GET 127.0.0.1:")
    assert spans[0]["type"] == "external"
    assert spans[0]["subtype"] == "http"
    assert url == spans[0]["context"]["http"]["url"]
    assert spans[0]["context"]["destination"]["service"] == {
        "name": "http://127.0.0.1:%d" % parsed_url.port,
        "resource": "127.0.0.1:%d" % parsed_url.port,
        "type": "external",
    }

    assert constants.TRACEPARENT_HEADER_NAME in waiting_httpserver.requests[0].headers
    trace_parent = TraceParent.from_string(waiting_httpserver.requests[0].headers[constants.TRACEPARENT_HEADER_NAME])
    assert trace_parent.trace_id == transactions[0]["trace_id"]

    # this should be the span id of `requests`, not of urllib3
    assert trace_parent.span_id == spans[0]["id"]
    assert trace_parent.trace_options.recorded


def test_requests_instrumentation_via_session(instrument, zuqa_client, waiting_httpserver):
    waiting_httpserver.serve_content("")
    url = waiting_httpserver.url + "/hello_world"
    zuqa_client.begin_transaction("transaction.test")
    with capture_span("test_request", "test"):
        s = requests.Session()
        s.get(url, allow_redirects=False)
    zuqa_client.end_transaction("MyView")

    transactions = zuqa_client.events[TRANSACTION]
    spans = zuqa_client.spans_for_transaction(transactions[0])
    assert spans[0]["name"].startswith("GET 127.0.0.1:")
    assert url == spans[0]["context"]["http"]["url"]

    assert constants.TRACEPARENT_HEADER_NAME in waiting_httpserver.requests[0].headers
    trace_parent = TraceParent.from_string(waiting_httpserver.requests[0].headers[constants.TRACEPARENT_HEADER_NAME])
    assert trace_parent.trace_id == transactions[0]["trace_id"]

    # this should be the span id of `requests`, not of urllib3
    assert trace_parent.span_id == spans[0]["id"]
    assert trace_parent.trace_options.recorded


def test_requests_instrumentation_via_prepared_request(instrument, zuqa_client, waiting_httpserver):
    waiting_httpserver.serve_content("")
    url = waiting_httpserver.url + "/hello_world"
    zuqa_client.begin_transaction("transaction.test")
    with capture_span("test_request", "test"):
        r = requests.Request("get", url)
        pr = r.prepare()
        s = requests.Session()
        s.send(pr, allow_redirects=False)
    zuqa_client.end_transaction("MyView")

    transactions = zuqa_client.events[TRANSACTION]
    spans = zuqa_client.spans_for_transaction(transactions[0])
    assert spans[0]["name"].startswith("GET 127.0.0.1:")
    assert url == spans[0]["context"]["http"]["url"]

    assert constants.TRACEPARENT_HEADER_NAME in waiting_httpserver.requests[0].headers
    trace_parent = TraceParent.from_string(waiting_httpserver.requests[0].headers[constants.TRACEPARENT_HEADER_NAME])
    assert trace_parent.trace_id == transactions[0]["trace_id"]

    # this should be the span id of `requests`, not of urllib3
    assert trace_parent.span_id == spans[0]["id"]
    assert trace_parent.trace_options.recorded


def test_requests_instrumentation_malformed_none(instrument, zuqa_client):
    zuqa_client.begin_transaction("transaction.test")
    with capture_span("test_request", "test"):
        with pytest.raises(MissingSchema):
            requests.get(None)


def test_requests_instrumentation_malformed_schema(instrument, zuqa_client):
    zuqa_client.begin_transaction("transaction.test")
    with capture_span("test_request", "test"):
        with pytest.raises(MissingSchema):
            requests.get("")


def test_requests_instrumentation_malformed_path(instrument, zuqa_client):
    zuqa_client.begin_transaction("transaction.test")
    with capture_span("test_request", "test"):
        with pytest.raises(InvalidURL):
            requests.get("http://")


def test_url_sanitization(instrument, zuqa_client, waiting_httpserver):
    waiting_httpserver.serve_content("")
    url = waiting_httpserver.url + "/hello_world"
    url = url.replace("http://", "http://user:pass@")
    transaction_object = zuqa_client.begin_transaction("transaction")
    requests.get(url)
    zuqa_client.end_transaction("MyView")
    transactions = zuqa_client.events[TRANSACTION]
    span = zuqa_client.spans_for_transaction(transactions[0])[0]

    assert "pass" not in span["context"]["http"]["url"]
    assert constants.MASK in span["context"]["http"]["url"]
