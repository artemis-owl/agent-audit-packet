package steering.decision

import rego.v1

default allow := false
default rationale := [{"code": "DEFAULT_DENY", "message": "Denied by default."}]

allow if {
    input.request.action == "build"
}

allow if {
    input.request.action == "deploy"
    input.request.environment == "dev"
    input.request.attributes.tests_passed == "true"
}

allow if {
    input.request.action == "deploy"
    input.request.environment == "prod"
    input.request.attributes.human_approved == "true"
}

rationale := [{"code": "ALLOW_BUILD", "message": "Local builds are unrestricted."}] if {
    input.request.action == "build"
}

rationale := [{"code": "ALLOW_DEPLOY_DEV", "message": "Dev deploy permitted because tests passed."}] if {
    input.request.action == "deploy"
    input.request.environment == "dev"
    input.request.attributes.tests_passed == "true"
}

rationale := [{"code": "ALLOW_DEPLOY_PROD", "message": "Prod deploy permitted by explicit human approval."}] if {
    input.request.action == "deploy"
    input.request.environment == "prod"
    input.request.attributes.human_approved == "true"
}

decision := {
    "allow": allow,
    "rationale": rationale
}
