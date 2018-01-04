package kapacitor

import (
	"bytes"
	"encoding/json"
	"fmt"
	html "html/template"
	"os"
	"sync"
	text "text/template"
	"time"

	"github.com/influxdata/kapacitor/alert"
	"github.com/influxdata/kapacitor/edge"
	"github.com/influxdata/kapacitor/expvar"
	"github.com/influxdata/kapacitor/keyvalue"
	"github.com/influxdata/kapacitor/models"
	"github.com/influxdata/kapacitor/pipeline"
	alertservice "github.com/influxdata/kapacitor/services/alert"
	"github.com/influxdata/kapacitor/services/hipchat"
	"github.com/influxdata/kapacitor/services/httppost"
	"github.com/influxdata/kapacitor/services/mqtt"
	"github.com/influxdata/kapacitor/services/opsgenie"
	"github.com/influxdata/kapacitor/services/pagerduty"
	"github.com/influxdata/kapacitor/services/pushover"
	"github.com/influxdata/kapacitor/services/sensu"
	"github.com/influxdata/kapacitor/services/slack"
	"github.com/influxdata/kapacitor/services/smtp"
	"github.com/influxdata/kapacitor/services/snmptrap"
	"github.com/influxdata/kapacitor/services/telegram"
	"github.com/influxdata/kapacitor/services/victorops"
	"github.com/influxdata/kapacitor/tick/ast"
	"github.com/influxdata/kapacitor/tick/stateful"
	"github.com/pkg/errors"
	"sort"
	"strconv"
	"path/filepath"
)

const (
	statsAlertsTriggered = "alerts_triggered"
	statsOKsTriggered    = "oks_triggered"
	statsInfosTriggered  = "infos_triggered"
	statsWarnsTriggered  = "warns_triggered"
	statsCritsTriggered  = "crits_triggered"
	statsEventsDropped   = "events_dropped"
)

// The newest state change is weighted 'weightDiff' times more than oldest state change.
const weightDiff = 1.5

// Maximum weight applied to newest state change.
const maxWeight = 1.2

type AlertNode struct {
	node
	a           *pipeline.AlertNode
	topic       string
	anonTopic   string
	handlers    []alert.Handler
	levels      []stateful.Expression
	scopePools  []stateful.ScopePool
	idTmpl      *text.Template
	messageTmpl *text.Template
	detailsTmpl *html.Template

	alertsTriggered *expvar.Int
	oksTriggered    *expvar.Int
	infosTriggered  *expvar.Int
	warnsTriggered  *expvar.Int
	critsTriggered  *expvar.Int
	eventsDropped   *expvar.Int

	bufPool sync.Pool

	levelResets  []stateful.Expression
	lrScopePools []stateful.ScopePool

	freeWarn *FreeWarn
}

/////////////freewarn/////////////
type FreeWarn struct {
	conf         string
	diag         NodeDiagnostic
	fwc          *FreeWarnConf
	currentLevel map[string]int
	buf          sync.Pool
}
type FreeWarnConf struct {
	Indexs   map[string]*WarnCondition `json:indexs`
	Tags     map[string]string         `json:"tags"`
	Alertdir string                    `json:"alertdir"`
}
type WarnCondition struct {
	Levels      map[string][]string `json:levels`
	Content     string              `json:content`
	ContentImpl *text.Template
	LevelsKey   []string
	Nodes       map[string][]*ast.LambdaNode
	Expressions map[string][]stateful.Expression
	ScopePools  map[string][]stateful.ScopePool
}

type ContentInfo struct {
	Tags   models.Tags
	Fields models.Fields
	Level  int
	Time   time.Time
}

func (fw FreeWarn) enabled() bool {
	return len(fw.conf) > 0
}

func (fw FreeWarn) setLevel(key string, level int) {
	ainfo := alertservice.AlertInfo{
		ID:   key,
		Info: strconv.Itoa(level),
	}
	err := alertservice.GetAlertInfoDAO().Put(ainfo)
	if err != nil {
		fw.diag.Error("AlertInfoDAO put error", err)
	}
	fw.currentLevel[key] = level
}

// 返回-1 表示没有获取到当前级别
func (fw FreeWarn) getLevel(key string) int {
	v, ok := fw.currentLevel[key]
	if !ok {
		ainfo, err := alertservice.GetAlertInfoDAO().Get(key)
		if err != nil {
			fw.diag.Error("AlertInfoDAO get error", err)
			return -1;
		}
		l, err := strconv.Atoi(ainfo.Info)
		if err != nil {
			fw.diag.Error("strconv.Atoi error", err)
			return -1;
		}
		fw.currentLevel[key] = l
		return l
	}
	return v
}

func (fw FreeWarn) log(bp edge.FieldsTagsTimeGetter, level int) {

	key := bp.Fields()["index"].(string) + "_" + bp.Fields()["identify"].(string)
	ekey := bp.Fields()["entity"].(string) + "_" + key

	file := fmt.Sprintf("%s/%d_%s.log", fw.fwc.Alertdir, bp.Time().Unix(), ekey)
	f, err := os.OpenFile(file, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0666)
	if err != nil {
		fw.diag.Error("failed to open file for alert logging", err, keyvalue.KV("file", file))
		return
	}
	defer f.Close()

	cinfo := &ContentInfo{
		Tags:   fw.fwc.Tags,
		Fields: bp.Fields(),
		Level:  level,
		Time:   bp.Time(),
	}

	tmpBuffer := fw.buf.Get().(*bytes.Buffer)
	defer func() {
		tmpBuffer.Reset()
		fw.buf.Put(tmpBuffer)
	}()
	tmpBuffer.Reset()

	err1 := fw.fwc.Indexs[key].ContentImpl.Execute(tmpBuffer, cinfo)
	if err1 != nil {
		fw.diag.Error("ContentImpl.Execute error", err)
		return
	}

	msg := tmpBuffer.String()
	f.Write([]byte(msg))

}

func (fw FreeWarn) init() error {

	err := json.Unmarshal([]byte(fw.conf), fw.fwc)
	if err != nil {
		return err
	}

	if !filepath.IsAbs(fw.fwc.Alertdir) {
		return fmt.Errorf("log path must be absolute: %s is not absolute", fw.fwc.Alertdir)
	}
	_, err = os.Stat(fw.fwc.Alertdir)
	if err != nil {
		//如果返回的错误为nil,说明文件或文件夹存在
		//如果返回的错误类型使用os.IsNotExist()判断为true,说明文件或文件夹不存在
		//如果返回的错误为其它类型,则不确定是否在存在
		//if os.IsNotExist(err) {
		//	return false, nil
		//}
		//return false, err
		return fmt.Errorf("log path must be exist: %s maybe not exist", fw.fwc.Alertdir)
	}

	for _, v := range fw.fwc.Indexs {

		v.LevelsKey = make([]string, len(v.Levels))
		v.Nodes = make(map[string][]*ast.LambdaNode)
		v.Expressions = make(map[string][]stateful.Expression)
		v.ScopePools = make(map[string][]stateful.ScopePool)

		index := 0
		for k1, v1 := range v.Levels {
			v.LevelsKey[index] = k1

			index++

			//生成lambda节点
			nodearr := make([]*ast.LambdaNode, len(v1))
			exprarr := make([]stateful.Expression, len(v1))
			scplarr := make([]stateful.ScopePool, len(v1))
			for i, v2 := range v1 {
				n, err1 := ast.ParseLambda(v2)
				if err1 != nil {
					return err1
				}
				nodearr[i] = n
				expr, err2 := stateful.NewExpression(n)
				if err2 != nil {
					return err2
				}
				exprarr[i] = expr

				scpl := stateful.NewScopePool(ast.FindReferenceVariables(n.Expression))
				scplarr[i] = scpl
			}
			v.Nodes[k1] = nodearr
			v.Expressions[k1] = exprarr
			v.ScopePools[k1] = scplarr

		}
		sort.Sort(sort.Reverse(sort.StringSlice(v.LevelsKey)))

		v.ContentImpl, err = text.New("content").Parse(v.Content)
		if err != nil {
			return err
		}
	}

	return nil
}

func (fw FreeWarn) determineLevel(bp edge.FieldsTagsTimeGetter) (int, bool) {
	key := bp.Fields()["index"].(string) + "_" + bp.Fields()["identify"].(string)
	wcd := fw.fwc.Indexs[key]
	for _, l := range wcd.LevelsKey {

		expr := wcd.Expressions[l]
		scpl := wcd.ScopePools[l]

		pass := 0
		for j, e := range expr {
			if p, err := EvalPredicate(e, scpl[j], bp); err != nil {
				pass = -1
				fw.diag.Error("error evaluating expression ", err)
			} else if p {
				pass = 1
			} else if !p {
				pass = 0
				break
			}
		}

		if pass == 1 {
			ln, err := strconv.Atoi(l)
			if err != nil {
				return -1, false
			}
			return ln, true
		}

	}

	return 0, true
}

/////////////

// Create a new  AlertNode which caches the most recent item and exposes it over the HTTP API.
func newAlertNode(et *ExecutingTask, n *pipeline.AlertNode, d NodeDiagnostic) (an *AlertNode, err error) {
	ctx := []keyvalue.T{
		keyvalue.KV("task", et.Task.ID),
	}

	an = &AlertNode{
		node: node{Node: n, et: et, diag: d},
		a:    n,
	}
	an.node.runF = an.runAlert

	an.topic = n.Topic
	// Create anonymous topic name
	an.anonTopic = fmt.Sprintf("%s:%s:%s", et.tm.ID(), et.Task.ID, an.Name())

	// Create buffer pool for the templates
	an.bufPool = sync.Pool{
		New: func() interface{} {
			return new(bytes.Buffer)
		},
	}

	// Parse templates
	an.idTmpl, err = text.New("id").Parse(n.Id)
	if err != nil {
		return nil, err
	}

	an.messageTmpl, err = text.New("message").Parse(n.Message)
	if err != nil {
		return nil, err
	}

	if len(n.FreeWarn) > 0 {
		//初始化 freewarn
		an.freeWarn = &FreeWarn{
			conf:         n.FreeWarn,
			diag:         d,
			currentLevel: make(map[string]int),
			buf: sync.Pool{
				New: func() interface{} {
					return new(bytes.Buffer)
				},
			},
			fwc: &FreeWarnConf{},
		}
		err = an.freeWarn.init()
		if err != nil {
			return nil, err
		}
	}
	an.detailsTmpl, err = html.New("details").Funcs(html.FuncMap{
		"json": func(v interface{}) html.JS {

			tmpBuffer := an.bufPool.Get().(*bytes.Buffer)
			defer func() {
				tmpBuffer.Reset()
				an.bufPool.Put(tmpBuffer)
			}()

			_ = json.NewEncoder(tmpBuffer).Encode(v)

			return html.JS(tmpBuffer.String())
		},
	}).Parse(n.Details)
	if err != nil {
		return nil, err
	}

	for _, tcp := range n.TcpHandlers {
		c := alertservice.TCPHandlerConfig{
			Address: tcp.Address,
		}
		h := alertservice.NewTCPHandler(c, an.diag)
		an.handlers = append(an.handlers, h)
	}

	for _, email := range n.EmailHandlers {
		c := smtp.HandlerConfig{
			To: email.ToList,
		}
		h := et.tm.SMTPService.Handler(c, ctx...)
		an.handlers = append(an.handlers, h)
	}
	if len(n.EmailHandlers) == 0 && (et.tm.SMTPService != nil && et.tm.SMTPService.Global()) {
		c := smtp.HandlerConfig{}
		h := et.tm.SMTPService.Handler(c, ctx...)
		an.handlers = append(an.handlers, h)
	}
	// If email has been configured with state changes only set it.
	if et.tm.SMTPService != nil &&
		et.tm.SMTPService.Global() &&
		et.tm.SMTPService.StateChangesOnly() {
		n.IsStateChangesOnly = true
	}

	for _, e := range n.ExecHandlers {
		c := alertservice.ExecHandlerConfig{
			Prog:      e.Command[0],
			Args:      e.Command[1:],
			Commander: et.tm.Commander,
		}
		h := alertservice.NewExecHandler(c, an.diag)
		an.handlers = append(an.handlers, h)
	}

	for _, log := range n.LogHandlers {
		c := alertservice.DefaultLogHandlerConfig()
		c.Path = log.FilePath
		if log.Mode != 0 {
			c.Mode = os.FileMode(log.Mode)
		}
		h, err := alertservice.NewLogHandler(c, an.diag)
		if err != nil {
			return nil, errors.Wrap(err, "failed to create log alert handler")
		}
		an.handlers = append(an.handlers, h)
	}

	for _, log := range n.MlogHandlers {
		c := alertservice.DefaultLogHandlerConfig()
		c.Path = log.FilePath
		if log.Mode != 0 {
			c.Mode = os.FileMode(log.Mode)
		}
		h, err := alertservice.NewMlogHandler(c, an.diag)
		if err != nil {
			return nil, errors.Wrap(err, "failed to create Mlog alert handler")
		}
		an.handlers = append(an.handlers, h)
	}

	for _, log := range n.PlogHandlers {
		c := alertservice.DefaultLogHandlerConfig()
		c.Path = log.FilePath
		if log.Mode != 0 {
			c.Mode = os.FileMode(log.Mode)
		}
		h, err := alertservice.NewPlogHandler(c, an.diag)
		if err != nil {
			return nil, errors.Wrap(err, "failed to create Plog alert handler")
		}
		an.handlers = append(an.handlers, h)
	}

	for _, vo := range n.VictorOpsHandlers {
		c := victorops.HandlerConfig{
			RoutingKey: vo.RoutingKey,
		}
		h := et.tm.VictorOpsService.Handler(c, ctx...)
		an.handlers = append(an.handlers, h)
	}
	if len(n.VictorOpsHandlers) == 0 && (et.tm.VictorOpsService != nil && et.tm.VictorOpsService.Global()) {
		c := victorops.HandlerConfig{}
		h := et.tm.VictorOpsService.Handler(c, ctx...)
		an.handlers = append(an.handlers, h)
	}

	for _, pd := range n.PagerDutyHandlers {
		c := pagerduty.HandlerConfig{
			ServiceKey: pd.ServiceKey,
		}
		h := et.tm.PagerDutyService.Handler(c, ctx...)
		an.handlers = append(an.handlers, h)
	}
	if len(n.PagerDutyHandlers) == 0 && (et.tm.PagerDutyService != nil && et.tm.PagerDutyService.Global()) {
		c := pagerduty.HandlerConfig{}
		h := et.tm.PagerDutyService.Handler(c, ctx...)
		an.handlers = append(an.handlers, h)
	}

	for _, s := range n.SensuHandlers {
		c := sensu.HandlerConfig{
			Source:   s.Source,
			Handlers: s.HandlersList,
		}
		h, err := et.tm.SensuService.Handler(c, ctx...)
		if err != nil {
			return nil, errors.Wrap(err, "failed to create sensu alert handler")
		}
		an.handlers = append(an.handlers, h)
	}

	for _, s := range n.SlackHandlers {
		c := slack.HandlerConfig{
			Channel:   s.Channel,
			Username:  s.Username,
			IconEmoji: s.IconEmoji,
		}
		h := et.tm.SlackService.Handler(c, ctx...)
		an.handlers = append(an.handlers, h)
	}
	if len(n.SlackHandlers) == 0 && (et.tm.SlackService != nil && et.tm.SlackService.Global()) {
		h := et.tm.SlackService.Handler(slack.HandlerConfig{}, ctx...)
		an.handlers = append(an.handlers, h)
	}
	// If slack has been configured with state changes only set it.
	if et.tm.SlackService != nil &&
		et.tm.SlackService.Global() &&
		et.tm.SlackService.StateChangesOnly() {
		n.IsStateChangesOnly = true
	}

	for _, t := range n.TelegramHandlers {
		c := telegram.HandlerConfig{
			ChatId:                t.ChatId,
			ParseMode:             t.ParseMode,
			DisableWebPagePreview: t.IsDisableWebPagePreview,
			DisableNotification:   t.IsDisableNotification,
		}
		h := et.tm.TelegramService.Handler(c, ctx...)
		an.handlers = append(an.handlers, h)
	}

	for _, s := range n.SNMPTrapHandlers {
		dataList := make([]snmptrap.Data, len(s.DataList))
		for i, d := range s.DataList {
			dataList[i] = snmptrap.Data{
				Oid:   d.Oid,
				Type:  d.Type,
				Value: d.Value,
			}
		}
		c := snmptrap.HandlerConfig{
			TrapOid:  s.TrapOid,
			DataList: dataList,
		}
		h, err := et.tm.SNMPTrapService.Handler(c, ctx...)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to create SNMP handler")
		}
		an.handlers = append(an.handlers, h)
	}

	if len(n.TelegramHandlers) == 0 && (et.tm.TelegramService != nil && et.tm.TelegramService.Global()) {
		c := telegram.HandlerConfig{}
		h := et.tm.TelegramService.Handler(c, ctx...)
		an.handlers = append(an.handlers, h)
	}
	// If telegram has been configured with state changes only set it.
	if et.tm.TelegramService != nil &&
		et.tm.TelegramService.Global() &&
		et.tm.TelegramService.StateChangesOnly() {
		n.IsStateChangesOnly = true
	}

	for _, hc := range n.HipChatHandlers {
		c := hipchat.HandlerConfig{
			Room:  hc.Room,
			Token: hc.Token,
		}
		h := et.tm.HipChatService.Handler(c, ctx...)
		an.handlers = append(an.handlers, h)
	}
	if len(n.HipChatHandlers) == 0 && (et.tm.HipChatService != nil && et.tm.HipChatService.Global()) {
		c := hipchat.HandlerConfig{}
		h := et.tm.HipChatService.Handler(c, ctx...)
		an.handlers = append(an.handlers, h)
	}
	// If HipChat has been configured with state changes only set it.
	if et.tm.HipChatService != nil &&
		et.tm.HipChatService.Global() &&
		et.tm.HipChatService.StateChangesOnly() {
		n.IsStateChangesOnly = true
	}

	for _, a := range n.AlertaHandlers {
		c := et.tm.AlertaService.DefaultHandlerConfig()
		if a.Token != "" {
			c.Token = a.Token
		}
		if a.Resource != "" {
			c.Resource = a.Resource
		}
		if a.Event != "" {
			c.Event = a.Event
		}
		if a.Environment != "" {
			c.Environment = a.Environment
		}
		if a.Group != "" {
			c.Group = a.Group
		}
		if a.Value != "" {
			c.Value = a.Value
		}
		if a.Origin != "" {
			c.Origin = a.Origin
		}
		if len(a.Service) != 0 {
			c.Service = a.Service
		}
		if a.Timeout != 0 {
			c.Timeout = a.Timeout
		}
		h, err := et.tm.AlertaService.Handler(c, ctx...)
		if err != nil {
			return nil, errors.Wrap(err, "failed to create Alerta handler")
		}
		an.handlers = append(an.handlers, h)
	}

	for _, p := range n.PushoverHandlers {
		c := pushover.HandlerConfig{}
		if p.Device != "" {
			c.Device = p.Device
		}
		if p.Title != "" {
			c.Title = p.Title
		}
		if p.URL != "" {
			c.URL = p.URL
		}
		if p.URLTitle != "" {
			c.URLTitle = p.URLTitle
		}
		if p.Sound != "" {
			c.Sound = p.Sound
		}
		h := et.tm.PushoverService.Handler(c, ctx...)
		an.handlers = append(an.handlers, h)
	}

	for _, p := range n.HTTPPostHandlers {
		c := httppost.HandlerConfig{
			URL:             p.URL,
			Endpoint:        p.Endpoint,
			Headers:         p.Headers,
			CaptureResponse: p.CaptureResponseFlag,
			Timeout:         p.Timeout,
		}
		h := et.tm.HTTPPostService.Handler(c, ctx...)
		an.handlers = append(an.handlers, h)
	}

	for _, og := range n.OpsGenieHandlers {
		c := opsgenie.HandlerConfig{
			TeamsList:      og.TeamsList,
			RecipientsList: og.RecipientsList,
		}
		h := et.tm.OpsGenieService.Handler(c, ctx...)
		an.handlers = append(an.handlers, h)
	}
	if len(n.OpsGenieHandlers) == 0 && (et.tm.OpsGenieService != nil && et.tm.OpsGenieService.Global()) {
		c := opsgenie.HandlerConfig{}
		h := et.tm.OpsGenieService.Handler(c, ctx...)
		an.handlers = append(an.handlers, h)
	}

	for range n.TalkHandlers {
		h := et.tm.TalkService.Handler(ctx...)
		an.handlers = append(an.handlers, h)
	}

	for _, m := range n.MQTTHandlers {
		c := mqtt.HandlerConfig{
			BrokerName: m.BrokerName,
			Topic:      m.Topic,
			QoS:        mqtt.QoSLevel(m.Qos),
			Retained:   m.Retained,
		}
		h := et.tm.MQTTService.Handler(c, ctx...)
		an.handlers = append(an.handlers, h)
	}
	// Parse level expressions
	an.levels = make([]stateful.Expression, alert.Critical+1)
	an.scopePools = make([]stateful.ScopePool, alert.Critical+1)

	an.levelResets = make([]stateful.Expression, alert.Critical+1)
	an.lrScopePools = make([]stateful.ScopePool, alert.Critical+1)

	if n.Info != nil {
		statefulExpression, expressionCompileError := stateful.NewExpression(n.Info.Expression)
		if expressionCompileError != nil {
			return nil, fmt.Errorf("Failed to compile stateful expression for info: %s", expressionCompileError)
		}

		an.levels[alert.Info] = statefulExpression
		an.scopePools[alert.Info] = stateful.NewScopePool(ast.FindReferenceVariables(n.Info.Expression))
		if n.InfoReset != nil {
			lstatefulExpression, lexpressionCompileError := stateful.NewExpression(n.InfoReset.Expression)
			if lexpressionCompileError != nil {
				return nil, fmt.Errorf("Failed to compile stateful expression for infoReset: %s", lexpressionCompileError)
			}
			an.levelResets[alert.Info] = lstatefulExpression
			an.lrScopePools[alert.Info] = stateful.NewScopePool(ast.FindReferenceVariables(n.InfoReset.Expression))
		}
	}

	if n.Warn != nil {
		statefulExpression, expressionCompileError := stateful.NewExpression(n.Warn.Expression)
		if expressionCompileError != nil {
			return nil, fmt.Errorf("Failed to compile stateful expression for warn: %s", expressionCompileError)
		}
		an.levels[alert.Warning] = statefulExpression
		an.scopePools[alert.Warning] = stateful.NewScopePool(ast.FindReferenceVariables(n.Warn.Expression))
		if n.WarnReset != nil {
			lstatefulExpression, lexpressionCompileError := stateful.NewExpression(n.WarnReset.Expression)
			if lexpressionCompileError != nil {
				return nil, fmt.Errorf("Failed to compile stateful expression for warnReset: %s", lexpressionCompileError)
			}
			an.levelResets[alert.Warning] = lstatefulExpression
			an.lrScopePools[alert.Warning] = stateful.NewScopePool(ast.FindReferenceVariables(n.WarnReset.Expression))
		}
	}

	if n.Crit != nil {
		statefulExpression, expressionCompileError := stateful.NewExpression(n.Crit.Expression)
		if expressionCompileError != nil {
			return nil, fmt.Errorf("Failed to compile stateful expression for crit: %s", expressionCompileError)
		}
		an.levels[alert.Critical] = statefulExpression
		an.scopePools[alert.Critical] = stateful.NewScopePool(ast.FindReferenceVariables(n.Crit.Expression))
		if n.CritReset != nil {
			lstatefulExpression, lexpressionCompileError := stateful.NewExpression(n.CritReset.Expression)
			if lexpressionCompileError != nil {
				return nil, fmt.Errorf("Failed to compile stateful expression for critReset: %s", lexpressionCompileError)
			}
			an.levelResets[alert.Critical] = lstatefulExpression
			an.lrScopePools[alert.Critical] = stateful.NewScopePool(ast.FindReferenceVariables(n.CritReset.Expression))
		}
	}

	// Setup states
	if n.History < 2 {
		n.History = 2
	}

	// Configure flapping
	if n.UseFlapping {
		if n.FlapLow > 1 || n.FlapHigh > 1 {
			return nil, errors.New("alert flap thresholds are percentages and should be between 0 and 1")
		}
	}

	return
}

func (n *AlertNode) runAlert([]byte) error {
	// Register delete hook
	if n.hasAnonTopic() {
		n.et.tm.registerDeleteHookForTask(n.et.Task.ID, deleteAlertHook(n.anonTopic))

		// Register Handlers on topic
		for _, h := range n.handlers {
			n.et.tm.AlertService.RegisterAnonHandler(n.anonTopic, h)
		}
		// Restore anonTopic
		n.et.tm.AlertService.RestoreTopic(n.anonTopic)
	}

	// Setup stats
	n.alertsTriggered = &expvar.Int{}
	n.statMap.Set(statsAlertsTriggered, n.alertsTriggered)

	n.oksTriggered = &expvar.Int{}
	n.statMap.Set(statsOKsTriggered, n.oksTriggered)

	n.infosTriggered = &expvar.Int{}
	n.statMap.Set(statsInfosTriggered, n.infosTriggered)

	n.warnsTriggered = &expvar.Int{}
	n.statMap.Set(statsWarnsTriggered, n.warnsTriggered)

	n.critsTriggered = &expvar.Int{}
	n.statMap.Set(statsCritsTriggered, n.critsTriggered)

	n.eventsDropped = &expvar.Int{}
	n.statMap.Set(statsCritsTriggered, n.critsTriggered)

	// Setup consumer
	consumer := edge.NewGroupedConsumer(
		n.ins[0],
		n,
	)
	n.statMap.Set(statCardinalityGauge, consumer.CardinalityVar())

	if err := consumer.Consume(); err != nil {
		return err
	}

	// Close the anonymous topic.
	n.et.tm.AlertService.CloseTopic(n.anonTopic)

	// Deregister Handlers on topic
	for _, h := range n.handlers {
		n.et.tm.AlertService.DeregisterAnonHandler(n.anonTopic, h)
	}
	return nil
}

func (n *AlertNode) NewGroup(group edge.GroupInfo, first edge.PointMeta) (edge.Receiver, error) {
	id, err := n.renderID(first.Name(), first.GroupID(), first.Tags())
	if err != nil {
		return nil, err
	}
	t := first.Time()

	state := n.restoreEventState(id, t)

	return edge.NewReceiverFromForwardReceiverWithStats(
		n.outs,
		edge.NewTimedForwardReceiver(
			n.timer,
			state,
		),
	), nil
}

func (n *AlertNode) restoreEventState(id string, t time.Time) *alertState {
	state := n.newAlertState()
	currentLevel, triggered := n.restoreEvent(id)
	if currentLevel != alert.OK {
		// Add initial event
		state.addEvent(t, currentLevel)
		// Record triggered time
		state.triggered(triggered)
	}
	return state
}

func (n *AlertNode) newAlertState() *alertState {
	return &alertState{
		history: make([]alert.Level, n.a.History),
		n:       n,
		buffer:  new(edge.BatchBuffer),
	}
}

func (n *AlertNode) restoreEvent(id string) (alert.Level, time.Time) {
	var topicState, anonTopicState alert.EventState
	var anonFound, topicFound bool
	// Check for previous state on anonTopic
	if n.hasAnonTopic() {
		if state, ok, err := n.et.tm.AlertService.EventState(n.anonTopic, id); err != nil {
			n.diag.Error("failed to get event state for anonymous topic", err,
				keyvalue.KV("topic", n.anonTopic), keyvalue.KV("event", id))
		} else if ok {
			anonTopicState = state
			anonFound = true
		}
	}
	// Check for previous state on topic.
	if n.hasTopic() {
		if state, ok, err := n.et.tm.AlertService.EventState(n.topic, id); err != nil {
			n.diag.Error("failed to get event state for topic", err,
				keyvalue.KV("topic", n.anonTopic), keyvalue.KV("event", id))
		} else if ok {
			topicState = state
			topicFound = true
		}
	}
	if topicState.Level != anonTopicState.Level {
		if anonFound && topicFound {
			// Anon topic takes precedence
			if err := n.et.tm.AlertService.UpdateEvent(n.topic, anonTopicState); err != nil {
				n.diag.Error("failed to update topic event state", err, keyvalue.KV("topic", n.topic), keyvalue.KV("event", id))
			}
		} else if topicFound && n.hasAnonTopic() {
			// Update event state for topic
			if err := n.et.tm.AlertService.UpdateEvent(n.anonTopic, topicState); err != nil {
				n.diag.Error("failed to update topic event state", err, keyvalue.KV("topic", n.topic), keyvalue.KV("event", id))
			}
		} // else nothing was found, nothing to do
	}
	if anonFound {
		return anonTopicState.Level, anonTopicState.Time
	}
	return topicState.Level, topicState.Time
}

func deleteAlertHook(anonTopic string) deleteHook {
	return func(tm *TaskMaster) {
		tm.AlertService.DeleteTopic(anonTopic)
	}
}

func (n *AlertNode) hasAnonTopic() bool {
	return len(n.handlers) > 0
}
func (n *AlertNode) hasTopic() bool {
	return n.topic != ""
}

func (n *AlertNode) handleEvent(event alert.Event) {
	n.alertsTriggered.Add(1)
	switch event.State.Level {
	case alert.OK:
		n.oksTriggered.Add(1)
	case alert.Info:
		n.infosTriggered.Add(1)
	case alert.Warning:
		n.warnsTriggered.Add(1)
	case alert.Critical:
		n.critsTriggered.Add(1)
	}
	n.diag.AlertTriggered(event.State.Level, event.State.ID, event.State.Message, event.Data.Result.Series[0])

	// If we have anon handlers, emit event to the anonTopic
	if n.hasAnonTopic() {
		event.Topic = n.anonTopic
		err := n.et.tm.AlertService.Collect(event)
		if err != nil {
			n.eventsDropped.Add(1)
			n.diag.Error("encountered error collecting event", err)
		}
	}

	// If we have a user define topic, emit event to the topic.
	if n.hasTopic() {
		event.Topic = n.topic
		err := n.et.tm.AlertService.Collect(event)
		if err != nil {
			n.eventsDropped.Add(1)
			n.diag.Error("encountered error collecting event", err)
		}
	}
}

func (n *AlertNode) determineLevel(p edge.FieldsTagsTimeGetter, currentLevel alert.Level) alert.Level {

	if higherLevel, found := n.findFirstMatchLevel(alert.Critical, currentLevel-1, p); found {
		return higherLevel
	}
	if rse := n.levelResets[currentLevel]; rse != nil {
		if pass, err := EvalPredicate(rse, n.lrScopePools[currentLevel], p); err != nil {
			n.diag.Error("error evaluating reset expression for current level", err, keyvalue.KV("level", currentLevel.String()))
		} else if !pass {
			return currentLevel
		}
	}
	if newLevel, found := n.findFirstMatchLevel(currentLevel, alert.OK, p); found {
		return newLevel
	}
	return alert.OK
}

func (n *AlertNode) findFirstMatchLevel(start alert.Level, stop alert.Level, p edge.FieldsTagsTimeGetter) (alert.Level, bool) {
	if stop < alert.OK {
		stop = alert.OK
	}
	for l := start; l > stop; l-- {
		se := n.levels[l]
		if se == nil {
			continue
		}
		if pass, err := EvalPredicate(se, n.scopePools[l], p); err != nil {
			n.diag.Error("error evaluating expression for level", err, keyvalue.KV("level", alert.Level(l).String()))
			continue
		} else if pass {
			return alert.Level(l), true
		}
	}
	return alert.OK, false
}

func (n *AlertNode) event(
	id, name string,
	group models.GroupID,
	tags models.Tags,
	fields models.Fields,
	level alert.Level,
	t time.Time,
	d time.Duration,
	result models.Result,
) (alert.Event, error) {
	msg, details, err := n.renderMessageAndDetails(id, name, t, group, tags, fields, level, d)
	if err != nil {
		return alert.Event{}, err
	}
	event := alert.Event{
		Topic: n.anonTopic,
		State: alert.EventState{
			ID:       id,
			Message:  msg,
			Details:  details,
			Time:     t,
			Duration: d,
			Level:    level,
		},
		Data: alert.EventData{
			Name:     name,
			TaskName: n.et.Task.ID,
			Group:    string(group),
			Tags:     tags,
			Fields:   fields,
			Result:   result,
		},
	}
	return event, nil
}

type alertState struct {
	n *AlertNode

	buffer *edge.BatchBuffer

	history []alert.Level
	idx     int

	flapping bool

	changed bool
	// Time when first alert was triggered
	firstTriggered time.Time
	// Time when last alert was triggered.
	// Note: Alerts are not triggered for every event.
	lastTriggered time.Time
	expired       bool
}

func (a *alertState) BeginBatch(begin edge.BeginBatchMessage) (edge.Message, error) {
	return nil, a.buffer.BeginBatch(begin)
}

func (a *alertState) BatchPoint(bp edge.BatchPointMessage) (edge.Message, error) {
	return nil, a.buffer.BatchPoint(bp)
}

func (a *alertState) EndBatch(end edge.EndBatchMessage) (edge.Message, error) {
	return a.BufferedBatch(a.buffer.BufferedBatchMessage(end))
}

func (a *alertState) BufferedBatch(b edge.BufferedBatchMessage) (edge.Message, error) {
	begin := b.Begin()
	id, err := a.n.renderID(begin.Name(), begin.GroupID(), begin.Tags())
	if err != nil {
		return nil, err
	}
	if len(b.Points()) == 0 {
		return nil, nil
	}

	//不能用原来的 level ， 只能单独处理了
	if nil != a.n.freeWarn && a.n.freeWarn.enabled() {
		lmap := make(map[string][]int)
		bpmap := make(map[string]edge.BatchPointMessage)
		for _, bp := range b.Points() {
			key := bp.Fields()["index"].(string) + "_" + bp.Fields()["identify"].(string)
			bpmap[key] = bp
			_, e := lmap[key]
			if !e {
				in := []int{-1, -1}
				lmap[key] = in
			}
			l, ok := a.n.freeWarn.determineLevel(bp)
			if ok {
				lmap[key][0] = lmap[key][1]
				lmap[key][1] = l
			}
		}
		for k, v := range lmap {
			if v[1] != -1 && v[1] == v[0] {
				//两次相同， 开始做判断是否告警
				l := a.n.freeWarn.getLevel(k)
				if (l == -1 && v[1] != 0 ) || (l != v[1]) {
					//没有查到历史级别,且当前级别不是0（正常）,要告警
					//或者 历史级别和当前级别不同，要告警
					a.n.freeWarn.setLevel(k, v[1])
					a.n.freeWarn.log(bpmap[k], v[1])
				}
			}
		}

	}

	// Keep track of lowest level for any point
	lowestLevel := alert.Critical
	// Keep track of highest level and point
	highestLevel := alert.OK
	var highestPoint edge.BatchPointMessage

	currentLevel := a.currentLevel()
	for _, bp := range b.Points() {
		l := a.n.determineLevel(bp, currentLevel)
		if l < lowestLevel {
			lowestLevel = l
		}
		if l > highestLevel || highestPoint == nil {
			highestLevel = l
			highestPoint = bp
		}
	}

	// Default the determined level to lowest.
	l := lowestLevel
	// Update determined level to highest if we don't care about all
	if !a.n.a.AllFlag {
		l = highestLevel
	}
	// Create alert Data
	t := highestPoint.Time()
	if a.n.a.AllFlag || l == alert.OK {
		t = begin.Time()
	}

	a.addEvent(t, l)

	// Trigger alert only if:
	//  l == OK and state.changed (aka recovery)
	//    OR
	//  l != OK and flapping/statechanges checkout
	if !(a.changed && l == alert.OK ||
		(l != alert.OK &&
			!((a.n.a.UseFlapping && a.flapping) ||
				(a.n.a.IsStateChangesOnly && !a.changed && !a.expired)))) {
		return nil, nil
	}

	a.triggered(t)

	// Suppress the recovery event.
	if a.n.a.NoRecoveriesFlag && l == alert.OK {
		return nil, nil
	}

	duration := a.duration()
	event, err := a.n.event(id, begin.Name(), begin.GroupID(), begin.Tags(), highestPoint.Fields(), l, t, duration, b.ToResult())
	if err != nil {
		return nil, err
	}

	a.n.handleEvent(event)

	// Update tags or fields with event state
	if a.n.a.LevelTag != "" ||
		a.n.a.LevelField != "" ||
		a.n.a.IdTag != "" ||
		a.n.a.IdField != "" ||
		a.n.a.DurationField != "" ||
		a.n.a.MessageField != "" {

		b = b.ShallowCopy()
		points := make([]edge.BatchPointMessage, len(b.Points()))
		for i, bp := range b.Points() {
			bp = bp.ShallowCopy()
			a.augmentTagsWithEventState(bp, event.State)
			a.augmentFieldsWithEventState(bp, event.State)
			points[i] = bp
		}
		b.SetPoints(points)

		newBegin := begin.ShallowCopy()
		a.augmentTagsWithEventState(newBegin, event.State)
		b.SetBegin(newBegin)
	}
	return b, nil
}

func (a *alertState) Point(p edge.PointMessage) (edge.Message, error) {
	id, err := a.n.renderID(p.Name(), p.GroupID(), p.Tags())
	if err != nil {
		return nil, err
	}
	l := a.n.determineLevel(p, a.currentLevel())

	a.addEvent(p.Time(), l)

	if (a.n.a.UseFlapping && a.flapping) || (a.n.a.IsStateChangesOnly && !a.changed && !a.expired) {
		return nil, nil
	}
	// send alert if we are not OK or we are OK and state changed (i.e recovery)
	if l != alert.OK || a.changed {
		a.triggered(p.Time())
		// Suppress the recovery event.
		if a.n.a.NoRecoveriesFlag && l == alert.OK {
			return nil, nil
		}
		// Create an alert event
		duration := a.duration()
		event, err := a.n.event(
			id,
			p.Name(),
			p.GroupID(),
			p.Tags(),
			p.Fields(),
			l,
			p.Time(),
			duration,
			p.ToResult(),
		)
		if err != nil {
			return nil, err
		}

		a.n.handleEvent(event)

		// Prepare an augmented point to return
		p = p.ShallowCopy()
		a.augmentTagsWithEventState(p, event.State)
		a.augmentFieldsWithEventState(p, event.State)
		return p, nil
	}
	return nil, nil
}

func (a *alertState) augmentTagsWithEventState(p edge.TagSetter, eventState alert.EventState) {
	if a.n.a.LevelTag != "" || a.n.a.IdTag != "" {
		tags := p.Tags().Copy()
		if a.n.a.LevelTag != "" {
			tags[a.n.a.LevelTag] = eventState.Level.String()
		}
		if a.n.a.IdTag != "" {
			tags[a.n.a.IdTag] = eventState.ID
		}
		p.SetTags(tags)
	}
}

func (a *alertState) augmentFieldsWithEventState(p edge.FieldSetter, eventState alert.EventState) {
	if a.n.a.LevelField != "" || a.n.a.IdField != "" || a.n.a.DurationField != "" || a.n.a.MessageField != "" {
		fields := p.Fields().Copy()
		if a.n.a.LevelField != "" {
			fields[a.n.a.LevelField] = eventState.Level.String()
		}
		if a.n.a.MessageField != "" {
			fields[a.n.a.MessageField] = eventState.Message
		}
		if a.n.a.IdField != "" {
			fields[a.n.a.IdField] = eventState.ID
		}
		if a.n.a.DurationField != "" {
			fields[a.n.a.DurationField] = int64(eventState.Duration)
		}
		p.SetFields(fields)
	}
}

func (a *alertState) Barrier(b edge.BarrierMessage) (edge.Message, error) {
	return b, nil
}
func (a *alertState) DeleteGroup(d edge.DeleteGroupMessage) (edge.Message, error) {
	return d, nil
}

// Return the duration of the current alert state.
func (a *alertState) duration() time.Duration {
	return a.lastTriggered.Sub(a.firstTriggered)
}

// Record that the alert was triggered at time t.
func (a *alertState) triggered(t time.Time) {
	a.lastTriggered = t
	// Check if we are being triggered for first time since an alert.OKAlert
	// If so reset firstTriggered time
	p := a.idx - 1
	if p == -1 {
		p = len(a.history) - 1
	}
	if a.history[p] == alert.OK {
		a.firstTriggered = t
	}
}

// Record an event in the alert history.
func (a *alertState) addEvent(t time.Time, level alert.Level) {
	// Check for changes
	a.changed = a.history[a.idx] != level

	// Add event to history
	a.idx = (a.idx + 1) % len(a.history)
	a.history[a.idx] = level

	a.updateFlapping()
	a.updateExpired(t)
}

// Return current level of this state
func (a *alertState) currentLevel() alert.Level {
	return a.history[a.idx]
}

// Compute the percentage change in the alert history.
func (a *alertState) percentChange() float64 {
	l := len(a.history)
	changes := 0.0
	weight := (maxWeight / weightDiff)
	step := (maxWeight - weight) / float64(l-1)
	for i := 0; i < l-1; i++ {
		// get current index
		c := (i + a.idx) % l
		// get previous index
		p := c - 1
		// check for wrap around
		if p < 0 {
			p = l - 1
		}
		if a.history[c] != a.history[p] {
			changes += weight
		}
		weight += step
	}

	p := changes / float64(l-1)
	return p
}

func (a *alertState) updateFlapping() {
	if !a.n.a.UseFlapping {
		return
	}
	p := a.percentChange()
	if a.flapping && p < a.n.a.FlapLow {
		a.flapping = false
	} else if !a.flapping && p > a.n.a.FlapHigh {
		a.flapping = true
	}
}

func (a *alertState) updateExpired(t time.Time) {
	a.expired = !a.changed && a.n.a.StateChangesOnlyDuration != 0 && t.Sub(a.lastTriggered) >= a.n.a.StateChangesOnlyDuration
}

type serverInfo struct {
	Hostname  string
	ClusterID string
	ServerID  string
}

// Type containing information available to ID template.
type idInfo struct {
	// Measurement name
	Name string

	// Task name
	TaskName string

	// Concatenation of all group-by tags of the form [key=value,]+.
	// If not groupBy is performed equal to literal 'nil'
	Group string

	// Map of tags
	Tags map[string]string

	ServerInfo serverInfo
}

type messageInfo struct {
	idInfo

	// The ID of the alert.
	ID string

	// Fields of alerting data point.
	Fields map[string]interface{}

	// Alert Level, one of: INFO, WARNING, CRITICAL.
	Level string

	// Time
	Time time.Time

	// Duration of the alert
	Duration time.Duration
}

type detailsInfo struct {
	messageInfo
	// The Message of the Alert
	Message string
}

func (n *AlertNode) serverInfo() serverInfo {
	return serverInfo{
		Hostname:  n.et.tm.ServerInfo.Hostname(),
		ClusterID: n.et.tm.ServerInfo.ClusterID().String(),
		ServerID:  n.et.tm.ServerInfo.ServerID().String(),
	}

}
func (n *AlertNode) renderID(name string, group models.GroupID, tags models.Tags) (string, error) {
	g := string(group)
	if group == models.NilGroup {
		g = "nil"
	}
	info := idInfo{
		Name:       name,
		TaskName:   n.et.Task.ID,
		Group:      g,
		Tags:       tags,
		ServerInfo: n.serverInfo(),
	}
	id := n.bufPool.Get().(*bytes.Buffer)
	defer func() {
		id.Reset()
		n.bufPool.Put(id)
	}()

	err := n.idTmpl.Execute(id, info)
	if err != nil {
		return "", err
	}
	return id.String(), nil
}

func (n *AlertNode) renderMessageAndDetails(id, name string, t time.Time, group models.GroupID, tags models.Tags, fields models.Fields, level alert.Level, d time.Duration) (string, string, error) {
	g := string(group)
	if group == models.NilGroup {
		g = "nil"
	}
	minfo := messageInfo{
		idInfo: idInfo{
			Name:       name,
			TaskName:   n.et.Task.ID,
			Group:      g,
			Tags:       tags,
			ServerInfo: n.serverInfo(),
		},
		ID:       id,
		Fields:   fields,
		Level:    level.String(),
		Time:     t,
		Duration: d,
	}

	// Grab a buffer for the message template and the details template
	tmpBuffer := n.bufPool.Get().(*bytes.Buffer)
	defer func() {
		tmpBuffer.Reset()
		n.bufPool.Put(tmpBuffer)
	}()
	tmpBuffer.Reset()

	err := n.messageTmpl.Execute(tmpBuffer, minfo)
	if err != nil {
		return "", "", err
	}

	msg := tmpBuffer.String()
	dinfo := detailsInfo{
		messageInfo: minfo,
		Message:     msg,
	}

	// Reuse the buffer, for the details template
	tmpBuffer.Reset()
	err = n.detailsTmpl.Execute(tmpBuffer, dinfo)
	if err != nil {
		return "", "", err
	}

	details := tmpBuffer.String()
	return msg, details, nil
}
