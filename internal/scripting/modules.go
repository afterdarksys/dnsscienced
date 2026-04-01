package scripting

import (
	"fmt"
	"time"

	"go.starlark.net/starlark"
	"go.starlark.net/starlarkstruct"
)

// buildThreatModule creates the threat.* module
func buildThreatModule() *starlarkstruct.Module {
	return &starlarkstruct.Module{
		Name: "threat",
		Members: starlark.StringDict{
			"check_ip":     starlark.NewBuiltin("threat.check_ip", threatCheckIP),
			"check_domain": starlark.NewBuiltin("threat.check_domain", threatCheckDomain),
			"check_hash":   starlark.NewBuiltin("threat.check_hash", threatCheckHash),
			"get_feed":     starlark.NewBuiltin("threat.get_feed", threatGetFeed),
			"submit_ioc":   starlark.NewBuiltin("threat.submit_ioc", threatSubmitIOC),
		},
	}
}

// buildFirewallModule creates the firewall.* module
func buildFirewallModule() *starlarkstruct.Module {
	return &starlarkstruct.Module{
		Name: "firewall",
		Members: starlark.StringDict{
			"block":       starlark.NewBuiltin("firewall.block", firewallBlock),
			"unblock":     starlark.NewBuiltin("firewall.unblock", firewallUnblock),
			"list_rules":  starlark.NewBuiltin("firewall.list_rules", firewallListRules),
			"add_rule":    starlark.NewBuiltin("firewall.add_rule", firewallAddRule),
			"delete_rule": starlark.NewBuiltin("firewall.delete_rule", firewallDeleteRule),
		},
	}
}

// buildLogModule creates the log.* module
func buildLogModule() *starlarkstruct.Module {
	return &starlarkstruct.Module{
		Name: "log",
		Members: starlark.StringDict{
			"debug":    starlark.NewBuiltin("log.debug", logDebug),
			"info":     starlark.NewBuiltin("log.info", logInfo),
			"warn":     starlark.NewBuiltin("log.warn", logWarn),
			"error":    starlark.NewBuiltin("log.error", logError),
			"alert":    starlark.NewBuiltin("log.alert", logAlert),
			"critical": starlark.NewBuiltin("log.critical", logCritical),
		},
	}
}

// buildNotifyModule creates the notify.* module
func buildNotifyModule() *starlarkstruct.Module {
	return &starlarkstruct.Module{
		Name: "notify",
		Members: starlark.StringDict{
			"slack":     starlark.NewBuiltin("notify.slack", notifySlack),
			"email":     starlark.NewBuiltin("notify.email", notifyEmail),
			"webhook":   starlark.NewBuiltin("notify.webhook", notifyWebhook),
			"pagerduty": starlark.NewBuiltin("notify.pagerduty", notifyPagerDuty),
		},
	}
}

// buildRuntimeModule creates the runtime.* module
func buildRuntimeModule() *starlarkstruct.Module {
	return &starlarkstruct.Module{
		Name: "runtime",
		Members: starlark.StringDict{
			"now":           starlark.NewBuiltin("runtime.now", runtimeNow),
			"timestamp":     starlark.NewBuiltin("runtime.timestamp", runtimeTimestamp),
			"get_variable":  starlark.NewBuiltin("runtime.get_variable", runtimeGetVariable),
			"get_script_id": starlark.NewBuiltin("runtime.get_script_id", runtimeGetScriptID),
			"sleep":         starlark.NewBuiltin("runtime.sleep", runtimeSleep),
		},
	}
}

// ===== Threat Module Implementation =====

func threatCheckIP(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var ip string
	if err := starlark.UnpackPositionalArgs(b.Name(), args, kwargs, 1, &ip); err != nil {
		return nil, err
	}

	result := starlark.NewDict(4)
	result.SetKey(starlark.String("ip"), starlark.String(ip))
	result.SetKey(starlark.String("score"), starlark.MakeInt(25))
	result.SetKey(starlark.String("category"), starlark.String("benign"))
	result.SetKey(starlark.String("malicious"), starlark.Bool(false))

	return result, nil
}

func threatCheckDomain(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var domain string
	if err := starlark.UnpackPositionalArgs(b.Name(), args, kwargs, 1, &domain); err != nil {
		return nil, err
	}

	result := starlark.NewDict(4)
	result.SetKey(starlark.String("domain"), starlark.String(domain))
	result.SetKey(starlark.String("score"), starlark.MakeInt(30))
	result.SetKey(starlark.String("category"), starlark.String("benign"))
	result.SetKey(starlark.String("malicious"), starlark.Bool(false))

	return result, nil
}

func threatCheckHash(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var hash string
	if err := starlark.UnpackPositionalArgs(b.Name(), args, kwargs, 1, &hash); err != nil {
		return nil, err
	}

	result := starlark.NewDict(3)
	result.SetKey(starlark.String("hash"), starlark.String(hash))
	result.SetKey(starlark.String("malicious"), starlark.Bool(false))
	result.SetKey(starlark.String("detections"), starlark.MakeInt(0))

	return result, nil
}

func threatGetFeed(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var feedName string
	if err := starlark.UnpackPositionalArgs(b.Name(), args, kwargs, 1, &feedName); err != nil {
		return nil, err
	}

	// Return mock feed data
	items := []starlark.Value{
		starlark.String("malicious1.com"),
		starlark.String("malicious2.com"),
	}

	return starlark.NewList(items), nil
}

func threatSubmitIOC(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var iocDict *starlark.Dict
	if err := starlark.UnpackPositionalArgs(b.Name(), args, kwargs, 1, &iocDict); err != nil {
		return nil, err
	}

	fmt.Printf("[ThreatScript] Threat IOC submitted: %v\n", iocDict)
	return starlark.Bool(true), nil
}

// ===== Firewall Module Implementation =====

func firewallBlock(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var ip string
	var port int
	var protocol string = "all"

	if err := starlark.UnpackArgs(b.Name(), args, kwargs,
		"ip", &ip,
		"port?", &port,
		"protocol?", &protocol,
	); err != nil {
		return nil, err
	}

	fmt.Printf("[ThreatScript] Firewall block: %s (port=%d, protocol=%s)\n", ip, port, protocol)
	return starlark.Bool(true), nil
}

func firewallUnblock(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var ip string
	if err := starlark.UnpackPositionalArgs(b.Name(), args, kwargs, 1, &ip); err != nil {
		return nil, err
	}

	fmt.Printf("[ThreatScript] Firewall unblock: %s\n", ip)
	return starlark.Bool(true), nil
}

func firewallListRules(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	// Return mock rules
	rules := []starlark.Value{}
	return starlark.NewList(rules), nil
}

func firewallAddRule(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var ruleDict *starlark.Dict
	if err := starlark.UnpackPositionalArgs(b.Name(), args, kwargs, 1, &ruleDict); err != nil {
		return nil, err
	}

	fmt.Printf("[ThreatScript] Firewall add_rule: %v\n", ruleDict)
	return starlark.Bool(true), nil
}

func firewallDeleteRule(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var ruleID string
	if err := starlark.UnpackPositionalArgs(b.Name(), args, kwargs, 1, &ruleID); err != nil {
		return nil, err
	}

	fmt.Printf("[ThreatScript] Firewall delete_rule: %s\n", ruleID)
	return starlark.Bool(true), nil
}

// ===== Log Module Implementation =====

func logDebug(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var message string
	if err := starlark.UnpackPositionalArgs(b.Name(), args, kwargs, 1, &message); err != nil {
		return nil, err
	}
	fmt.Printf("[DEBUG] %s\n", message)
	return starlark.None, nil
}

func logInfo(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var message string
	if err := starlark.UnpackPositionalArgs(b.Name(), args, kwargs, 1, &message); err != nil {
		return nil, err
	}
	fmt.Printf("[INFO] %s\n", message)
	return starlark.None, nil
}

func logWarn(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var message string
	if err := starlark.UnpackPositionalArgs(b.Name(), args, kwargs, 1, &message); err != nil {
		return nil, err
	}
	fmt.Printf("[WARN] %s\n", message)
	return starlark.None, nil
}

func logError(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var message string
	if err := starlark.UnpackPositionalArgs(b.Name(), args, kwargs, 1, &message); err != nil {
		return nil, err
	}
	fmt.Printf("[ERROR] %s\n", message)
	return starlark.None, nil
}

func logAlert(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var message string
	if err := starlark.UnpackPositionalArgs(b.Name(), args, kwargs, 1, &message); err != nil {
		return nil, err
	}
	fmt.Printf("[ALERT] %s\n", message)
	return starlark.None, nil
}

func logCritical(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var message string
	if err := starlark.UnpackPositionalArgs(b.Name(), args, kwargs, 1, &message); err != nil {
		return nil, err
	}
	fmt.Printf("[CRITICAL] %s\n", message)
	return starlark.None, nil
}

// ===== Notify Module Implementation =====

func notifySlack(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var message string
	if err := starlark.UnpackPositionalArgs(b.Name(), args, kwargs, 1, &message); err != nil {
		return nil, err
	}
	fmt.Printf("[Slack] %s\n", message)
	return starlark.Bool(true), nil
}

func notifyEmail(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var to, subject, body string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs,
		"to", &to,
		"subject", &subject,
		"body", &body,
	); err != nil {
		return nil, err
	}
	fmt.Printf("[Email] To=%s Subject=%s\n", to, subject)
	return starlark.Bool(true), nil
}

func notifyWebhook(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var url string
	var data *starlark.Dict
	if err := starlark.UnpackArgs(b.Name(), args, kwargs,
		"url", &url,
		"data", &data,
	); err != nil {
		return nil, err
	}
	fmt.Printf("[Webhook] URL=%s Data=%v\n", url, data)
	return starlark.Bool(true), nil
}

func notifyPagerDuty(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var description string
	if err := starlark.UnpackPositionalArgs(b.Name(), args, kwargs, 1, &description); err != nil {
		return nil, err
	}
	fmt.Printf("[PagerDuty] %s\n", description)
	return starlark.Bool(true), nil
}

// ===== Runtime Module Implementation =====

func runtimeNow(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	return starlark.String(time.Now().Format(time.RFC3339)), nil
}

func runtimeTimestamp(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	return starlark.MakeInt(int(time.Now().Unix())), nil
}

func runtimeGetVariable(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var name string
	if err := starlark.UnpackPositionalArgs(b.Name(), args, kwargs, 1, &name); err != nil {
		return nil, err
	}
	// Return from thread locals or global context
	return starlark.String(""), nil
}

func runtimeGetScriptID(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	return starlark.String("script-001"), nil
}

func runtimeSleep(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var seconds int
	if err := starlark.UnpackPositionalArgs(b.Name(), args, kwargs, 1, &seconds); err != nil {
		return nil, err
	}

	if seconds > 5 {
		return nil, fmt.Errorf("sleep duration cannot exceed 5 seconds")
	}

	time.Sleep(time.Duration(seconds) * time.Second)
	return starlark.None, nil
}
