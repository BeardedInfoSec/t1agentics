"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'code_1' block
    code_1(container=container)

    return

@phantom.playbook_block()
def code_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("code_1() called")

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.act"])

    container_artifact_cef_item_0 = [item[0] for item in container_artifact_data]

    input_parameter_0 = "test_input_static_input"

    code_1__test_output = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    
    import json
    from datetime import datetime
    
    # Normalize artifact actions
    normalized_results = []
    risk_score = 0
    
    for act in container_artifact_cef_item_0:
        if not act:
            continue
    
        act_lower = str(act).lower()
        category = "other"
        score = 10
    
        if "login" in act_lower:
            category = "authentication"
            score = 20
        elif "command" in act_lower or "execute" in act_lower:
            category = "command_execution"
            score = 60
        elif "download" in act_lower:
            category = "file_transfer"
            score = 40
        elif "delete" in act_lower:
            category = "destructive_action"
            score = 70
    
        risk_score += score
    
        normalized_results.append({
            "activity": act,
            "category": category,
            "risk_score": score,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        })
    
    # Cap score for demo purposes
    risk_score = min(risk_score, 100)
    
    # Final demo output
    code_1__test_output = {
        "total_activities": len(normalized_results),
        "overall_risk_score": risk_score,
        "verdict": (
            "High Risk" if risk_score >= 70 else
            "Medium Risk" if risk_score >= 40 else
            "Low Risk"
        ),
        "activities": normalized_results
    }
    
    
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_block_result(key="code_1__inputs:0:test_input_static_input", value=json.dumps("test_input_static_input"))
    phantom.save_block_result(key="code_1__inputs:1:artifact:*.cef.act", value=json.dumps(container_artifact_cef_item_0))

    phantom.save_block_result(key="code_1:test_output", value=json.dumps(code_1__test_output))

    phantom.save_block_result(key="code_1_called", value="True")

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