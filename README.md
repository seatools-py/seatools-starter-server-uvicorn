# seatools uvicorn 服务器

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
3. 程序直接调用

```python
from xxx.boot import start
from seatools.ioc.server import uvicorn


def main():
    uvicorn.run(
        start,
        'xxx.fastapi.app:app' # 配置中seatools.server.uvicorn.app配置此处可不填
    )


if __name__ == '__main__':
    main()

```
4. 支持配置`config/application.yml`
```yaml
seatools:
  server:
    uvicorn:
      # 配置该参数后启动参数可忽略app参数, 配置与官方uvicorn.run一致,  
      app: xxx.fastapi.app:app
      host: 127.0.0.1
      port: 8000
      workers: 1
      # ...
    
```