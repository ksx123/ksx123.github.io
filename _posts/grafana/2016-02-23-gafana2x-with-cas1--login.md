---
layout: post
title: "Gafana2.x With CAS(1)--Login"
description: ""
category: "grafana" 
tags: []
---
{% include JB/setup %}


## 0.前言 grafana
Grafana是开源的，功能齐全的度量仪表盘和图形编辑器，支持 Graphite，InfluxDB 和 OpenTSDB等数据源。  
从Grafana2.0开始加入使用Golang实现的后端服务，该后端支持用户登入，认证方式有GitHub、Google、LDAP却不支持CAS方式登入。

## 1.新增配置

在`conf/defaults.ini`中增加以下内容(默认关闭CAS登入)

```INI
#################################### Auth CAS ##########################
[auth.cas]
enabled = false
server_url = http://localhost/
```

修改`pkg/setting/setting.go`, 定义CAS登入相关设置变量:

```golang
// Auth CAS settings
AuthCasEnabled   bool
AuthCasServerUrl string
```

在方法`NewConfigContext(args *CommandLineArgs)`中加入变量初始化:

```golang
// auth cas
authCas := Cfg.Section("auth.cas")
AuthCasEnabled = authCas.Key("enabled").MustBool(false)
AuthCasServerUrl = authCas.Key("server_url").String()
```

## 2.CAS登入Handler
在`Godeps/Godeps.json`中添加如下依赖并运行 `godep restore`:

```json
{
  "ImportPath": "github.com/lucasuyezu/golang-cas-client",
  "Rev": "546569006c117b2f553f5a7ec0b4fe41f3dddc05"
}
```

在 `pkg/login`下创建`cas.go`文件内容如下:

```golang
package login

import (
  "net/url"

  "github.com/grafana/grafana/pkg/bus"
  "github.com/grafana/grafana/pkg/log"
  "github.com/grafana/grafana/pkg/middleware"
  m "github.com/grafana/grafana/pkg/models"
  "github.com/grafana/grafana/pkg/setting"
  "github.com/grafana/grafana/pkg/util"
  "github.com/lucasuyezu/golang-cas-client"
)

func loginUserWithCas(user *m.User, c *middleware.Context) {
  if user == nil {
    log.Error(3, "User login with nil user")
  }

  days := 86400 * setting.LogInRememberDays
  c.SetCookie(setting.CookieUserName, user.Login, days, setting.AppSubUrl+"/")
  c.SetSuperSecureCookie(util.EncodeMd5(user.Rands+user.Password), setting.CookieRememberName, user.Login, days, setting.AppSubUrl+"/")

  c.Session.Set(middleware.SESS_KEY_USERID, user.Id)
}

func getService() string {
  return setting.AppUrl + "login"
}

func CasLogin(c *middleware.Context) {

  service := getService()

  ticket := c.Query("ticket")
  if len(ticket) == 0 {
    c.Redirect(setting.AuthCasServerUrl + "/login?service=" + service)
    return
  }

  cas := cas.NewService(setting.AuthCasServerUrl, service)
  response, _ := cas.ValidateServiceTicket(ticket)
  if response.Status {

    userQuery := m.GetUserByLoginQuery{LoginOrEmail: response.User}
    err := bus.Dispatch(&userQuery)

    if err != nil {
      cmd := m.CreateUserCommand{
        Email: response.Email,
        Name: response.User,
        Login: response.User,
        Password: "",
      }
      if err := bus.Dispatch(&cmd); err != nil {
        c.JsonApiErr(500, "failed to create user", err)
        return
      }
      bus.Dispatch(&userQuery)
    }

    user := userQuery.Result
    loginUserWithCas(user, c)

    if redirectTo, _ := url.QueryUnescape(c.GetCookie("redirect_to")); len(redirectTo) > 0 {
      c.SetCookie("redirect_to", "", -1, setting.AppSubUrl+"/")
      c.Redirect(redirectTo)
      return
    }

    c.Redirect(setting.AppSubUrl + "/")
  } else {
    c.Redirect("/")
  }
}
```

## 3.拦截登入请求
在开启CAS登入后，原登入逻辑应替换为CAS的登入逻辑，在`pkg/api/login.go`的`LoginView(c *middleware.Context)`方法最前面加入:

```golang
if setting.AuthCasEnabled {
  login.CasLogin(c)
  return
}
```

## 4.总结
至此，使用CAS登入Grafana已经实现，下一篇会讲述如何为Grafana增加CAS单点登出。