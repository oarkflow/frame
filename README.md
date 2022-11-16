# Frame

English | [中文](README_cn.md)

[![Release](https://img.shields.io/github/v/release/cloudwego/frame)](https://github.com/sujit-baniya/frame/releases)
[![WebSite](https://img.shields.io/website?up_message=cloudwego&url=https%3A%2F%2Fwww.cloudwego.io%2F)](https://www.cloudwego.io/)
[![License](https://img.shields.io/github/license/cloudwego/frame)](https://github.com/sujit-baniya/frame/blob/main/LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/sujit-baniya/frame)](https://goreportcard.com/report/github.com/sujit-baniya/frame)
[![OpenIssue](https://img.shields.io/github/issues/cloudwego/frame)](https://github.com/sujit-baniya/frame/issues)
[![ClosedIssue](https://img.shields.io/github/issues-closed/cloudwego/frame)](https://github.com/sujit-baniya/frame/issues?q=is%3Aissue+is%3Aclosed)
![Stars](https://img.shields.io/github/stars/cloudwego/frame)
![Forks](https://img.shields.io/github/forks/cloudwego/frame)


Frame [həːts] is a high-usability, high-performance and high-extensibility Golang HTTP framework that helps developers build microservices. It was designed with reference to other open-source frameworks like [fasthttp](https://github.com/valyala/fasthttp), [gin](https://github.com/gin-gonic/gin), [echo](https://github.com/labstack/echo) and combined with the internal requirements in ByteDance. At present, it has been widely used inside ByteDance. Nowadays, more and more microservices use Golang. If you have requirements for microservice performance and hope that the framework can fully meet the internal customizable requirements, Frame will be a good choice.
## Basic Features
- High usability

  During the development process, it is often more important to write the correct code quickly. Therefore, in the iterative process of Frame, we actively listen to users' opinions and continue to polish the framework, hoping to provide users with a better user experience and help users write correct code faster.
- High performance

  Frame uses the self-developed high-performance network library Netpoll by default. In some special scenarios, compared to Go Net, Frame has certain advantages in QPS and time delay. For performance data, please refer to the Echo data in the figure below.

  Comparison of four frameworks:
  ![Performance](images/performance-4.png)
  Comparison of three frameworks:
  ![Performance](images/performance-3.png)
  For detailed performance data, please refer to [frame-benchmark](https://github.com/sujit-baniya/frame-benchmark).
- High extensibility

  Frame adopts a layered design, providing more interfaces and default extension implementations. Users can also extend by themselves. At the same time, thanks to the layered design of the framework, the extensibility of the framework will be much greater. At present, only stable capabilities are open-sourced to the community. More planning refers to [RoadMap](ROADMAP.md).
- Multi-protocol support

  The Frame framework provides HTTP1.1, ALPN protocol support natively. In addition, due to the layered design, Frame even supports custom build protocol resolution logic to meet any needs of protocol layer extensions.
- Network layer switching capability

  Frame implements the function to switch between Netpoll and Go Net on demand. Users can choose the appropriate network library for different scenarios. And Frame also supports the extension of network library in the form of plug-ins.
## Documentation
### [Getting Started](https://www.cloudwego.io/docs/frame/getting-started/)
### Example
  The Frame-Examples repository provides code out of the box. [more](https://www.cloudwego.io/zh/docs/frame/tutorials/example/)
### Basic Features
  Contains introduction and use of general middleware, context selection, data binding, data rendering, direct access, logging, error handling. [more](https://www.cloudwego.io/zh/docs/frame/tutorials/basic-feature/)
### Service Governance
  Contains tracer monitor. [more](https://www.cloudwego.io/zh/docs/frame/tutorials/service-governance/)
### Framework Extension
  Contains network library extensions. [more](https://www.cloudwego.io/zh/docs/frame/tutorials/framework-exten/)
### Reference
  Apidoc, framework configurable items list. [more](https://www.cloudwego.io/zh/docs/frame/reference/)
### FAQ
  Frequently Asked Questions. [more](https://www.cloudwego.io/zh/docs/frame/faq/)
## Performance
  Performance testing can only provide a relative reference. In production, there are many factors that can affect actual performance.
  We provide the frame-benchmark project to track and compare the performance of Frame and other frameworks in different situations for reference.
## Related Projects
- [Netpoll](https://github.com/cloudwego/netpoll): A high-performance network library. Frame integrated by default.
- [Frame-Contrib](https://github.com/frame-contrib): A partial extension library of Frame, which users can integrate into Frame through options according to their needs.
- [Example](https://github.com/sujit-baniya/frame-examples): Use examples of Frame.
## Extensions

| Extensions                                                                                         | Description                                                                                                                                                             |
|----------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| [Websocket](https://github.com/frame-contrib/websocket)                                            | Enable Frame to support the Websocket protocol.                                                                                                                         |
| [Pprof](https://github.com/frame-contrib/pprof)                                                    | Extension for Frame integration with Pprof.                                                                                                                             |
| [Sessions](https://github.com/frame-contrib/sessions)                                              | Session middleware with multi-state store support.                                                                                                                      |
| [Obs-opentelemetry](https://github.com/frame-contrib/obs-opentelemetry)                            | Frame's Opentelemetry extension that supports Metric, Logger, Tracing and works out of the box.                                                                         |
| [Registry](https://github.com/frame-contrib/registry)                                              | Provides service registry and discovery functions. So far, the supported service discovery extensions are nacos, consul, etcd, eureka, polaris, servicecomb, zookeeper. |
| [Keyauth](https://github.com/frame-contrib/keyauth)                                                | Provides token-based authentication.                                                                                                                                    |
| [Secure](https://github.com/frame-contrib/secure)                                                  | Secure middleware with multiple configuration items.                                                                                                                    |
| [Sentry](https://github.com/frame-contrib/framesentry)                                             | Sentry extension provides some unified interfaces to help users perform real-time error monitoring.                                                                     |
| [Requestid](https://github.com/frame-contrib/requestid)                                            | Add request id in response.                                                                                                                                             |
| [Limiter](https://github.com/frame-contrib/limiter)                                                | Provides a current limiter based on the bbr algorithm.                                                                                                                  |
| [Jwt](https://github.com/frame-contrib/jwt)                                                        | Jwt extension.                                                                                                                                                          |
| [Autotls](https://github.com/frame-contrib/autotls)                                                | Make Frame support Let's Encrypt.                                                                                                                                       |
| [Monitor-prometheus](https://github.com/frame-contrib/monitor-prometheus)                          | Provides service monitoring based on Prometheus.                                                                                                                        |
| [I18n](https://github.com/frame-contrib/i18n)                                                      | Helps translate Frame programs into multi programming languages.                                                                                                        |
| [Reverseproxy](https://github.com/frame-contrib/reverseproxy)                                      | Implement a reverse proxy.                                                                                                                                              |
| [Opensergo](https://github.com/frame-contrib/opensergo)                                            | The Opensergo extension.                                                                                                                                                |
| [Gzip](https://github.com/frame-contrib/gzip)                                                      | A Gzip extension with multiple options.                                                                                                                                 |
| [Cors](https://github.com/frame-contrib/cors)                                                      | Provides cross-domain resource sharing support.                                                                                                                         |
| [Swagger](https://github.com/frame-contrib/swagger)                                                | Automatically generate RESTful API documentation with Swagger 2.0.                                                                                                      |
| [Tracer](https://github.com/frame-contrib/tracer)                                                  | Link tracing based on Opentracing.                                                                                                                                      |
| [Recovery](https://github.com/sujit-baniya/frame/tree/develop/pkg/app/middlewares/server/recovery)    | Recovery middleware for Frame.                                                                                                                                          |
| [Basicauth](https://github.com/sujit-baniya/frame/tree/develop/pkg/app/middlewares/server/basic_auth) | Basicauth middleware can provide HTTP basic authentication.                                                                                                             |
| [Lark](https://github.com/frame-contrib/lark-frame)                                                | Use frame handle Lark/Feishu card message and event callback.                                                                                                           |
| [Logger](https://github.com/frame-contrib/logger)                                                  | Logger extension for Frame, which provides support for third-party logging frameworks.                                                                                  |

## Blogs
- [ByteDance Practice on Go Network Library](https://www.cloudwego.io/blog/2021/10/09/bytedance-practices-on-go-network-library/)
## Contributing

[Contributing](https://github.com/sujit-baniya/frame/blob/main/CONTRIBUTING.md)
## RoadMap
[Frame RoadMap](ROADMAP.md)
## License
Frame is distributed under the [Apache License, version 2.0](https://github.com/sujit-baniya/frame/blob/main/LICENSE). The licenses of third party dependencies of Frame are explained [here](https://github.com/sujit-baniya/frame/blob/main/licenses).
## Community
- Email: [conduct@cloudwego.io](conduct@cloudwego.io)
- How to become a member: [COMMUNITY MEMBERSHIP](https://github.com/cloudwego/community/blob/main/COMMUNITY_MEMBERSHIP.md)
- Issues: [Issues](https://github.com/sujit-baniya/frame/issues)
- Slack: Join our CloudWeGo community [Slack Channel](https://join.slack.com/t/cloudwego/shared_invite/zt-tmcbzewn-UjXMF3ZQsPhl7W3tEDZboA).
- Lark: Scan the QR code below with [Lark](https://www.larksuite.com/zh_cn/download) to join our CloudWeGo/frame user group.

![LarkGroup](images/lark_group.png)
- WeChat: CloudWeGo community WeChat group.

![WechatGroup](images/wechat_group_cn.png)
## Contributors
Thank you for your contribution to Frame!

[![Contributors](https://contrib.rocks/image?repo=cloudwego/frame)](https://github.com/sujit-baniya/frame/graphs/contributors)
## Landscapes

<p align="center">
<img src="https://landscape.cncf.io/images/left-logo.svg" width="150"/>&nbsp;&nbsp;<img src="https://landscape.cncf.io/images/right-logo.svg" width="200"/>
<br/><br/>
CloudWeGo enriches the <a href="https://landscape.cncf.io/">CNCF CLOUD NATIVE Landscape</a>.
</p>
