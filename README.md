# seatools uvicorn 服务器启动器

该框架在`uvicorn`层完成`seatools.ioc`的加载, 使用该项目后无需在每个进程额外执行`seatools.ioc.run`函数, 仅在启动时传递一个`ioc`启动的函数即可

## 使用指南
1. 安装, `poetry add seatools-starter-server-uvicorn`
2. 这里以`fastapi`为例, 假设`xxx.boot`模块存在`start`的自定义启动`ioc`函数

```python
from seatools.ioc import run


def start():
    run(scan_package_names='xxx', config_dir='./config')

```
命令行启动`uvicorn xxx.boot:start xxx.fastapi.app:app`, 其他参数与官方`uvicorn`一致, 在`uvicorn`基础上增加了一个`ioc_app`的参数, 需要指明`ioc`应用启动的函数
若配置`application.yml`或`application-[*].yml`中存在`seatools.server.uvicorn.app`配置, 则可不传递`uvicorn`的`app`仅传递`ioc_app`即可, 示例`uvicorn xxx.boot:start`
若同时使用了`seatools-starter-web-*`的`web`启动包, 则`uvicorn`的`app`直接可省略
3. 程序直接调用

```python
from xxx.boot import start
from seatools.ioc.server import uvicorn


def main():
    uvicorn.run(
        start,
        'xxx.fastapi.app:app' # 配置中seatools.server.uvicorn.app存在 或 安装了seatools-starter-web-fastapi 此处可不填
    )


if __name__ == '__main__':
    main()

```
4. 支持配置`config/application.yml`
```yaml
seatools:
  server:
    uvicorn:
      # 配置该参数后启动参数可忽略app参数, 配置与官方uvicorn.run一致, 若安装 seatools-starter-web-fastapi可省略app配置 
      app: xxx.fastapi.app:app
      host: 127.0.0.1
      port: 8000
      workers: 1
      # ...
    
```