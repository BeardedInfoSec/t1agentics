"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'regex_extract_dotted_email_1' block
    regex_extract_dotted_email_1(container=container)
    # call 'regex_extract_ipv4_deduplicate_4' block
    regex_extract_ipv4_deduplicate_4(container=container)
    # call 'regex_extract_url_deduplicate_5' block
    regex_extract_url_deduplicate_5(container=container)

    return

@phantom.playbook_block()
def cef_to_json_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("cef_to_json_2() called")

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef","artifact:*.id"])
    format_1 = phantom.get_format_data(name="format_1")

    container_artifact_header_item_0 = [item[0] for item in container_artifact_data]

    parameters = []

    parameters.append({
        "container": container_artifact_header_item_0,
        "extracted_fields": format_1,
        "servicenow_field_list": "ServiceNow",
        "servicenow_comment_fields": ["ServiceNow_Comment_Fields"],
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="local/cef_to_json", parameters=parameters, name="cef_to_json_2", callback=debug_3)

    return


@phantom.playbook_block()
def debug_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("debug_3() called")

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef","artifact:*.id"])
    cef_to_json_2__result = phantom.collect2(container=container, datapath=["cef_to_json_2:custom_function_result.data.cleaned_json"])

    container_artifact_header_item_0 = [item[0] for item in container_artifact_data]
    cef_to_json_2_data_cleaned_json = [item[0] for item in cef_to_json_2__result]

    parameters = []

    parameters.append({
        "input_1": container_artifact_header_item_0,
        "input_2": cef_to_json_2_data_cleaned_json,
        "input_3": None,
        "input_4": None,
        "input_5": None,
        "input_6": None,
        "input_7": None,
        "input_8": None,
        "input_9": None,
        "input_10": None,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/debug", parameters=parameters, name="debug_3")

    return


@phantom.playbook_block()
def regex_extract_dotted_email_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("regex_extract_dotted_email_1() called")

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.ioc_test_string","artifact:*.id"])

    parameters = []

    # build parameters list for 'regex_extract_dotted_email_1' call
    for container_artifact_item in container_artifact_data:
        parameters.append({
            "input_string": container_artifact_item[0],
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="local/regex_extract_dotted_email", parameters=parameters, name="regex_extract_dotted_email_1", callback=join_format_1)

    return


@phantom.playbook_block()
def regex_extract_ipv4_deduplicate_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("regex_extract_ipv4_deduplicate_4() called")

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.ioc_test_string","artifact:*.id"])

    parameters = []

    # build parameters list for 'regex_extract_ipv4_deduplicate_4' call
    for container_artifact_item in container_artifact_data:
        parameters.append({
            "input_string": container_artifact_item[0],
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="local/regex_extract_ipv4_deduplicate", parameters=parameters, name="regex_extract_ipv4_deduplicate_4", callback=join_format_1)

    return


@phantom.playbook_block()
def regex_extract_url_deduplicate_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("regex_extract_url_deduplicate_5() called")

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.ioc_test_string","artifact:*.id"])

    parameters = []

    # build parameters list for 'regex_extract_url_deduplicate_5' call
    for container_artifact_item in container_artifact_data:
        parameters.append({
            "input_string": container_artifact_item[0],
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="local/regex_extract_url_deduplicate", parameters=parameters, name="regex_extract_url_deduplicate_5", callback=join_format_1)

    return


@phantom.playbook_block()
def join_format_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("join_format_1() called")

    if phantom.completed(custom_function_names=["regex_extract_dotted_email_1", "regex_extract_ipv4_deduplicate_4", "regex_extract_url_deduplicate_5"]):
        # call connected block "format_1"
        format_1(container=container, handle=handle)

    return


@phantom.playbook_block()
def format_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_1() called")

    template = """\"emails\": \"{0}\",\n\"ipv4\": \"{1}\",\n\"url\": \"{2}\",\n\"domain\": \"{3}\"\n"""

    # parameter list for template variable replacement
    parameters = [
        "regex_extract_dotted_email_1:custom_function_result.data.*.email_address",
        "regex_extract_ipv4_deduplicate_4:custom_function_result.data.extracted_ipv4",
        "regex_extract_url_deduplicate_5:custom_function_result.data.extracted_url",
        "regex_extract_dotted_email_1:custom_function_result.data.*.domain"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_1", drop_none=True)

    cef_to_json_2(container=container)

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    return