"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'list_external_dynamic_acl' block
    list_external_dynamic_acl(container=container)

    return

@phantom.playbook_block()
def list_external_dynamic_acl(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("list_external_dynamic_acl() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    parameters = []

    parameters.append({
        "device_group": "shared",
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("list edl", parameters=parameters, name="list_external_dynamic_acl", assets=["pano"], callback=get_external_dynamic_acl)

    return


@phantom.playbook_block()
def get_external_dynamic_acl(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("get_external_dynamic_acl() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    list_external_dynamic_acl_result_data = phantom.collect2(container=container, datapath=["list_external_dynamic_acl:action_result.data.*.@name","list_external_dynamic_acl:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'get_external_dynamic_acl' call
    for list_external_dynamic_acl_result_item in list_external_dynamic_acl_result_data:
        if list_external_dynamic_acl_result_item[0] is not None:
            parameters.append({
                "name": list_external_dynamic_acl_result_item[0],
                "device_group": "shared",
                "context": {'artifact_id': list_external_dynamic_acl_result_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("get edl", parameters=parameters, name="get_external_dynamic_acl", assets=["pano"], callback=filter_1)

    return


@phantom.playbook_block()
def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("filter_1() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.destinationAddress", "not in", "list_external_dynamic_acl:action_result.data.*.type.ip.recurring.monthly.at.#text"]
        ],
        name="filter_1:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        malicious_ips(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids and results for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.requestURL", "not in", "list_external_dynamic_acl:action_result.data.*.type.ip.url.#text"]
        ],
        name="filter_1:condition_2",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        malicious_urls(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return


@phantom.playbook_block()
def block_ip_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("block_ip_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    audit_comment_formatted_string = phantom.format(
        container=container,
        template="""Malicious IP Found: {0}\nSOAR Ticket: {1}\n""",
        parameters=[
            "filtered-data:filter_1:condition_1:artifact:*.cef.destinationAddress",
            "container:id"
        ])

    id_value = container.get("id", None)
    filtered_artifact_0_data_filter_1 = phantom.collect2(container=container, datapath=["filtered-data:filter_1:condition_1:artifact:*.cef.destinationAddress","filtered-data:filter_1:condition_1:artifact:*.id"])
    get_external_dynamic_acl_result_data = phantom.collect2(container=container, datapath=["get_external_dynamic_acl:action_result.parameter.device_group","get_external_dynamic_acl:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'block_ip_1' call
    for filtered_artifact_0_item_filter_1 in filtered_artifact_0_data_filter_1:
        for get_external_dynamic_acl_result_item in get_external_dynamic_acl_result_data:
            if filtered_artifact_0_item_filter_1[0] is not None and get_external_dynamic_acl_result_item[0] is not None:
                parameters.append({
                    "ip": filtered_artifact_0_item_filter_1[0],
                    "policy_type": "Block",
                    "device_group": get_external_dynamic_acl_result_item[0],
                    "audit_comment": audit_comment_formatted_string,
                    "should_add_tag": True,
                    "use_partial_commit": True,
                    "should_commit_changes": True,
                    "context": {'artifact_id': filtered_artifact_0_item_filter_1[1]},
                })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("block ip", parameters=parameters, name="block_ip_1", assets=["pano"], callback=ip_commit)

    return


@phantom.playbook_block()
def block_url_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("block_url_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    audit_comment_formatted_string = phantom.format(
        container=container,
        template="""Malicious URL Found: {0}\nSOAR Ticket: {1}\n""",
        parameters=[
            "filtered-data:filter_1:condition_2:list_edl_1:artifact:*.cef.requestURL",
            "container:id"
        ])

    id_value = container.get("id", None)
    filtered_artifact_0_data_filter_1 = phantom.collect2(container=container, datapath=["filtered-data:filter_1:condition_2:artifact:*.cef.requestURL","filtered-data:filter_1:condition_2:artifact:*.id"])
    filtered_artifact_1_data_filter_1 = phantom.collect2(container=container, datapath=["filtered-data:filter_1:condition_2:list_edl_1:artifact:*.cef.requestURL","filtered-data:filter_1:condition_2_list_edl_1:artifact:*.id"])
    get_external_dynamic_acl_result_data = phantom.collect2(container=container, datapath=["get_external_dynamic_acl:action_result.parameter.device_group","get_external_dynamic_acl:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'block_url_1' call
    for filtered_artifact_0_item_filter_1 in filtered_artifact_0_data_filter_1:
        for get_external_dynamic_acl_result_item in get_external_dynamic_acl_result_data:
            for filtered_artifact_1_item_filter_1 in filtered_artifact_1_data_filter_1:
                if filtered_artifact_0_item_filter_1[0] is not None and get_external_dynamic_acl_result_item[0] is not None:
                    parameters.append({
                        "url": filtered_artifact_0_item_filter_1[0],
                        "policy_type": "Block",
                        "device_group": get_external_dynamic_acl_result_item[0],
                        "audit_comment": audit_comment_formatted_string,
                        "use_partial_commit": True,
                        "should_commit_changes": True,
                        "context": {'artifact_id': filtered_artifact_1_item_filter_1[1]},
                    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("block url", parameters=parameters, name="block_url_1", assets=["pano"], callback=url_commit)

    return


@phantom.playbook_block()
def join_prompt_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("join_prompt_1() called")

    if phantom.completed(action_names=["get_external_dynamic_acl"]):
        # call connected block "prompt_1"
        prompt_1(container=container, handle=handle)

    return


@phantom.playbook_block()
def prompt_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("prompt_1() called")

    # set approver and message variables for phantom.prompt call

    user = container.get('owner_name', None)
    role = None
    message = """Malicious IOCs are not currently blocked on the firewall.\nIP: {0}\n\nURL: {1}"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_1:condition_2:list_edl_1:artifact:*.cef.destinationAddress",
        "filtered-data:filter_1:condition_2:list_edl_1:artifact:*.cef.requestURL"
    ]

    # responses
    response_types = [
        {
            "prompt": "Block IPs?",
            "options": {
                "type": "list",
                "required": True,
                "choices": [
                    "Yes",
                    "No"
                ],
            },
        },
        {
            "prompt": "Block URLs?",
            "options": {
                "type": "list",
                "required": True,
                "choices": [
                    "Yes",
                    "No"
                ],
            },
        }
    ]

    phantom.prompt2(container=container, user=user, role=role, message=message, respond_in_mins=30, name="prompt_1", parameters=parameters, response_types=response_types, callback=filter_3)

    return


@phantom.playbook_block()
def malicious_ips(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("malicious_ips() called")

    template = """{0}\n"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_1:condition_1:list_edl_1:artifact:*.cef.destinationAddress"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="malicious_ips", drop_none=True)

    join_prompt_1(container=container)

    return


@phantom.playbook_block()
def malicious_urls(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("malicious_urls() called")

    template = """{0}\n"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_1:condition_2:list_edl_1:artifact:*.cef.requestURL"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="malicious_urls")

    join_prompt_1(container=container)

    return


@phantom.playbook_block()
def filter_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("filter_3() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["prompt_1:action_result.summary.responses.0", "==", "Yes"]
        ],
        name="filter_3:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        block_ip_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids and results for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        conditions=[
            ["prompt_1:action_result.summary.responses.1", "==", "Yes"]
        ],
        name="filter_3:condition_2",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        block_url_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return


@phantom.playbook_block()
def ip_commit(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("ip_commit() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    get_external_dynamic_acl_result_data = phantom.collect2(container=container, datapath=["get_external_dynamic_acl:action_result.parameter.device_group","get_external_dynamic_acl:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'ip_commit' call
    for get_external_dynamic_acl_result_item in get_external_dynamic_acl_result_data:
        if get_external_dynamic_acl_result_item[0] is not None:
            parameters.append({
                "device_group": get_external_dynamic_acl_result_item[0],
                "use_partial_commit": True,
                "context": {'artifact_id': get_external_dynamic_acl_result_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("commit changes", parameters=parameters, name="ip_commit", assets=["pano"], callback=ip_commit_status)

    return


@phantom.playbook_block()
def url_commit(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("url_commit() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    list_external_dynamic_acl_result_data = phantom.collect2(container=container, datapath=["list_external_dynamic_acl:action_result.parameter.device_group","list_external_dynamic_acl:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'url_commit' call
    for list_external_dynamic_acl_result_item in list_external_dynamic_acl_result_data:
        if list_external_dynamic_acl_result_item[0] is not None:
            parameters.append({
                "device_group": list_external_dynamic_acl_result_item[0],
                "context": {'artifact_id': list_external_dynamic_acl_result_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("commit changes", parameters=parameters, name="url_commit", assets=["pano"], callback=url_commit_status)

    return


@phantom.playbook_block()
def ip_status_update_ticket(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("ip_status_update_ticket() called")

    ip_commit_status = phantom.get_format_data(name="ip_commit_status")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment=ip_commit_status)

    join_check_for_successful_commit(container=container)

    return


@phantom.playbook_block()
def ip_commit_status(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("ip_commit_status() called")

    template = """The IP Commit {0}\n"""

    # parameter list for template variable replacement
    parameters = [
        "ip_commit:action_result.status"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="ip_commit_status")

    ip_status_update_ticket(container=container)

    return


@phantom.playbook_block()
def url_commit_status(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("url_commit_status() called")

    template = """The URL Commit {0}\n"""

    # parameter list for template variable replacement
    parameters = [
        "url_commit:artifact:*.cef.act"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="url_commit_status")

    url_status_update_ticket(container=container)

    return


@phantom.playbook_block()
def url_status_update_ticket(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("url_status_update_ticket() called")

    url_commit_status = phantom.get_format_data(name="url_commit_status")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment=url_commit_status)

    join_check_for_successful_commit(container=container)

    return


@phantom.playbook_block()
def set_severity_high(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("set_severity_high() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.set_severity(container=container, severity="high")

    container = phantom.get_container(container.get('id', None))

    return


@phantom.playbook_block()
def join_check_for_successful_commit(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("join_check_for_successful_commit() called")

    if phantom.completed(action_names=["ip_commit", "url_commit"]):
        # call connected block "check_for_successful_commit"
        check_for_successful_commit(container=container, handle=handle)

    return


@phantom.playbook_block()
def check_for_successful_commit(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("check_for_successful_commit() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        logical_operator="or",
        conditions=[
            ["url_commit:action_result.status", "!=", "success"],
            ["ip_commit:action_result.status", "!=", "success"]
        ],
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        set_severity_high(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    set_status_6(action=action, success=success, container=container, results=results, handle=handle)

    return


@phantom.playbook_block()
def set_status_6(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("set_status_6() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.set_status(container=container, status="closed")

    container = phantom.get_container(container.get('id', None))

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