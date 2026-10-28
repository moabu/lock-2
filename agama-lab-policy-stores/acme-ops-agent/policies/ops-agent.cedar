@id("block-untrusted-agent")
@reason("An agent that is not trusted is never allowed to act.")
forbid(principal, action, resource is AcmeOps::Resource)
when { !(context has tokens) && principal is AcmeOps::Agent && !principal.trusted };

@id("block-suspicious-request")
@reason("A request flagged as suspicious, such as a likely prompt injection, is blocked.")
forbid(principal, action, resource is AcmeOps::Resource)
when { context.suspicious };

@id("block-customer-export")
@reason("Bulk customer exports are never allowed for an agent.")
forbid(principal, action == AcmeOps::Action::"ExportCustomers", resource is AcmeOps::Resource);

@id("read-customer-on-ticket")
@reason("An agent may read only the customer on the ticket assigned to the person it acts for.")
permit(principal, action == AcmeOps::Action::"ReadCustomer", resource is AcmeOps::Resource)
when {
  !(context has tokens) &&
  principal is AcmeOps::Agent &&
  resource.kind == "customer-record" &&
  resource.customer == context.ticket_customer &&
  context.ticket_assignee == principal.acting_for
};

@id("deploy-staging-on-call")
@reason("An on-call SRE agent may deploy the workload named in the change to staging.")
permit(principal, action == AcmeOps::Action::"Deploy", resource is AcmeOps::Resource)
when {
  !(context has tokens) &&
  principal is AcmeOps::Agent &&
  resource.kind == "workload" &&
  resource.environment == "staging" &&
  principal.role == "sre" &&
  principal.on_call &&
  context.change_workload == resource.workload
};

@id("deploy-prod-approved-change")
@reason("An SRE agent may deploy to production only for an approved change while a human is on call.")
permit(principal, action == AcmeOps::Action::"Deploy", resource is AcmeOps::Resource)
when {
  !(context has tokens) &&
  principal is AcmeOps::Agent &&
  resource.kind == "workload" &&
  resource.environment == "prod" &&
  principal.role == "sre" &&
  context.change_approved &&
  context.human_on_call &&
  context.change_workload == resource.workload
};

@id("read-customer-on-ticket-token")
@reason("A signed-in user may read only the customer on the ticket assigned to them.")
permit(principal, action == AcmeOps::Action::"ReadCustomer", resource is AcmeOps::Resource)
when {
  context has tokens &&
  context.tokens has acme_userinfo_token &&
  context.tokens.acme_userinfo_token has given_name &&
  resource.kind == "customer-record" &&
  resource.customer == context.ticket_customer &&
  context.ticket_assignee == context.tokens.acme_userinfo_token.given_name
};

@id("deploy-staging-token")
@reason("A signed-in admin may deploy the workload named in the change to staging.")
permit(principal, action == AcmeOps::Action::"Deploy", resource is AcmeOps::Resource)
when {
  context has tokens &&
  context.tokens has acme_userinfo_token &&
  context.tokens.acme_userinfo_token has role &&
  context.tokens.acme_userinfo_token.role.contains("admin") &&
  resource.kind == "workload" &&
  resource.environment == "staging" &&
  context.change_workload == resource.workload
};

@id("deploy-prod-approved-change-token")
@reason("A signed-in admin may deploy to production only for an approved change while a human is on call.")
permit(principal, action == AcmeOps::Action::"Deploy", resource is AcmeOps::Resource)
when {
  context has tokens &&
  context.tokens has acme_userinfo_token &&
  context.tokens.acme_userinfo_token has role &&
  context.tokens.acme_userinfo_token.role.contains("admin") &&
  resource.kind == "workload" &&
  resource.environment == "prod" &&
  context.change_approved &&
  context.human_on_call &&
  context.change_workload == resource.workload
};
