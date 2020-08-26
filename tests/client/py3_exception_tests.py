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

#  BSD 3-Clause License
#
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions are met:
#
#
#
#

import mock

from zuqa.conf.constants import ERROR


def test_chained_cause_exception(zuqa_client):
    try:
        try:
            1 / 0
        except ZeroDivisionError as zde:
            raise ValueError("bla") from zde
    except ValueError:
        zuqa_client.capture_exception()
    error = zuqa_client.events[ERROR][0]
    assert error["exception"]["type"] == "ValueError"
    assert error["exception"]["cause"][0]["type"] == "ZeroDivisionError"


def test_chained_context_exception(zuqa_client):
    try:
        try:
            1 / 0
        except ZeroDivisionError:
            int("zero")
    except ValueError:
        zuqa_client.capture_exception()
    error = zuqa_client.events[ERROR][0]
    assert error["exception"]["type"] == "ValueError"
    assert error["exception"]["cause"][0]["type"] == "ZeroDivisionError"


def test_chained_context_exception_suppressed(zuqa_client):
    try:
        try:
            1 / 0
        except ZeroDivisionError:
            raise ValueError("bla") from None
    except ValueError:
        zuqa_client.capture_exception()
    error = zuqa_client.events[ERROR][0]
    assert error["exception"]["type"] == "ValueError"
    assert "cause" not in error["exception"]


def test_chained_context_exception_max(zuqa_client):
    with mock.patch("zuqa.events.EXCEPTION_CHAIN_MAX_DEPTH", 1):
        try:
            try:
                1 / 0
            except ZeroDivisionError:
                try:
                    1 + "a"
                except TypeError as e:
                    raise ValueError("bla") from e
        except ValueError:
            zuqa_client.capture_exception()
        error = zuqa_client.events[ERROR][0]
        assert error["exception"]["type"] == "ValueError"
        assert error["exception"]["cause"][0]["type"] == "TypeError"
        assert "cause" not in error["exception"]["cause"][0]
