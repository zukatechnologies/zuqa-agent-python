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
"""
Instrumentation for Tornado
"""
import zuqa
from zuqa.conf import constants
from zuqa.instrumentation.packages.asyncio.base import AbstractInstrumentedModule, AsyncAbstractInstrumentedModule
from zuqa.traces import capture_span
from zuqa.utils.disttracing import TraceParent


class TornadoRequestExecuteInstrumentation(AsyncAbstractInstrumentedModule):
    name = "tornado_request_execute"
    creates_transactions = True
    instrument_list = [("tornado.web", "RequestHandler._execute")]

    async def call(self, module, method, wrapped, instance, args, kwargs):
        if not hasattr(instance.application, "zuqa_client"):
            # If tornado was instrumented but not as the main framework
            # (i.e. in Flower), we should skip it.
            return await wrapped(*args, **kwargs)

        # Late import to avoid ImportErrors
        from zuqa.contrib.tornado.utils import get_data_from_request, get_data_from_response

        request = instance.request
        trace_parent = TraceParent.from_headers(request.headers)
        client = instance.application.zuqa_client
        client.begin_transaction("request", trace_parent=trace_parent)
        zuqa.set_context(
            lambda: get_data_from_request(instance, request, client.config, constants.TRANSACTION), "request"
        )
        # TODO: Can we somehow incorporate the routing rule itself here?
        zuqa.set_transaction_name("{} {}".format(request.method, type(instance).__name__), override=False)

        ret = await wrapped(*args, **kwargs)

        zuqa.set_context(
            lambda: get_data_from_response(instance, client.config, constants.TRANSACTION), "response"
        )
        result = "HTTP {}xx".format(instance.get_status() // 100)
        zuqa.set_transaction_result(result, override=False)
        client.end_transaction()

        return ret


class TornadoHandleRequestExceptionInstrumentation(AbstractInstrumentedModule):
    name = "tornado_handle_request_exception"

    instrument_list = [("tornado.web", "RequestHandler._handle_request_exception")]

    def call(self, module, method, wrapped, instance, args, kwargs):
        if not hasattr(instance.application, "zuqa_client"):
            # If tornado was instrumented but not as the main framework
            # (i.e. in Flower), we should skip it.
            return wrapped(*args, **kwargs)

        # Late import to avoid ImportErrors
        from tornado.web import Finish, HTTPError
        from zuqa.contrib.tornado.utils import get_data_from_request

        e = args[0]
        if isinstance(e, Finish):
            # Not an error; Finish is an exception that ends a request without an error response
            return wrapped(*args, **kwargs)

        client = instance.application.zuqa_client
        request = instance.request
        client.capture_exception(
            context={"request": get_data_from_request(instance, request, client.config, constants.ERROR)}
        )
        if isinstance(e, HTTPError):
            zuqa.set_transaction_result("HTTP {}xx".format(int(e.status_code / 100)), override=False)
            zuqa.set_context({"status_code": e.status_code}, "response")
        else:
            zuqa.set_transaction_result("HTTP 5xx", override=False)
            zuqa.set_context({"status_code": 500}, "response")

        return wrapped(*args, **kwargs)


class TornadoRenderInstrumentation(AbstractInstrumentedModule):
    name = "tornado_render"

    instrument_list = [("tornado.web", "RequestHandler.render")]

    def call(self, module, method, wrapped, instance, args, kwargs):
        if "template_name" in kwargs:
            name = kwargs["template_name"]
        else:
            name = args[0]

        with capture_span(name, span_type="template", span_subtype="tornado", span_action="render"):
            return wrapped(*args, **kwargs)