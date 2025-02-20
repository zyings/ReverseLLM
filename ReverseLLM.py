import functools
import idaapi
import ida_hexrays
import ida_kernwin
import idc
import openai
import re
import threading
import json
import httpx
import sys, os

PLUGIN_NAME = "ReverseLLM"

class ModelConfig:
    def __init__(self):
        config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ModelConfig.json")
        self.config_path = config_path
        self.load_config()
        
    def load_config(self):
        with open(self.config_path) as f:
            config = json.load(f)
            self.models = {m["name"]: m for m in config["models"]}
            self.current_model = config["default_model"]
            self.client = self.switch_model(self.current_model)
    
    def switch_model(self, model_name):
        if model_name not in self.models:
            raise ValueError(f"Model {model_name} not found in config")
            
        model = self.models[model_name]
        self.current_model = model_name
        self.display_name = model.get("display_name", model_name)
        self.base_url = model.get("base_url", model_name)
        self.api_key = model.get("api_key", model_name)
        self.proxy = model.get("proxy", model_name)
        # Update global client
        if "proxy" in model and model["proxy"]:
            http_client = httpx.Client(transport=httpx.HTTPTransport(proxy=model["proxy"]))
            client = openai.OpenAI(
                base_url=model["base_url"],
                api_key=model["api_key"],
                http_client=http_client
            )
        else:
            client = openai.OpenAI(
                base_url=model["base_url"],
                api_key=model["api_key"]
            )
        return client

    def get_current_model(self):
        return self.models[self.current_model]
config=ModelConfig()

class SwitchModelHandler(idaapi.action_handler_t):
    def __init__(self, modelname):
        idaapi.action_handler_t.__init__(self)
        self.model_name = modelname
    def activate(self, ctx):
        global config
        config.client=config.switch_model(self.model_name)
        print(f"模型切换为：{config.display_name}")
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

# ReverseLLM 分析解释函数
class ExplainHandler(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        # print(MODEL)
        funcComment = getFuncComment(idaapi.get_screen_ea())
        if "---GPT_START---" in funcComment:
            print("当前函数已经完成过 %s:Explain 分析，请查看注释或删除注释重新分析。@小火车yyds"%(PLUGIN_NAME))
            return 0
        decompiler_output = ida_hexrays.decompile(idaapi.get_screen_ea())
        v = ida_hexrays.get_widget_vdui(ctx.widget)
        query_model_async("下面是一个C语言伪代码函数，分别分析该函数的预期目的、参数的作用、详细功能，最后取一个新的函数名字。（用简体中文回答我，并且回答开始前加上'---GPT_START---'字符串结束后加上'---GPT_END---'字符串）\n"
                + str(decompiler_output),
                functools.partial(comment_callback, address=idaapi.get_screen_ea(), view=v, cmtFlag=0, printFlag=0),
                0)
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


# ReverseLLM 重命名变量函数
class RenameHandler(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        decompiler_output = ida_hexrays.decompile(idaapi.get_screen_ea())
        v = ida_hexrays.get_widget_vdui(ctx.widget)
        query_model_async("Analyze the following C function:\n" + str(decompiler_output) +
                            "\nSuggest better variable names, reply with a JSON array where keys are the original names"
                            "and values are the proposed names. Do not explain anything, only print the JSON "
                            "dictionary.",
                          functools.partial(rename_callback, address=idaapi.get_screen_ea(), view=v),
                          0)
        return 1

    # This action is always available.
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


# ReverseLLM 使用python3对函数进行还原
class PythonHandler(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        # lastAddr 为函数的最后一行汇编代码地址
        lastAddr = idc.prev_head(idc.get_func_attr(idaapi.get_screen_ea(), idc.FUNCATTR_END))
        # 获取对应注释
        addrComment = getAddrComment(lastAddr)
        if "---GPT_Python_START---" in str(addrComment):
            print("当前函数已经完成过 %s:Python 分析，请查看注释或删除注释重新分析。@小火车yyds"%(PLUGIN_NAME))
            return 0
        decompiler_output = ida_hexrays.decompile(idaapi.get_screen_ea())
        v = ida_hexrays.get_widget_vdui(ctx.widget)
        # 中文
        query_model_async("分析下面的C语言伪代码并用python3代码进行还原。（回答开始前加上'---GPT_Python_START---'字符串结束后加上'---GPT_Python_END---'字符串）\n"
                + str(decompiler_output),
                functools.partial(comment_callback, address=lastAddr, view=v, cmtFlag=1, printFlag=1),
                0)
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


# ReverseLLM 尝试寻找函数漏洞
class FindVulnHandler(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        funcComment = getFuncComment(idaapi.get_screen_ea())
        if "---GPT_VulnFinder_START---" in funcComment:
            print("当前函数已经完成过 %s:VulnFinder 分析，请查看注释或删除注释重新分析。@小火车yyds"%(PLUGIN_NAME))
            return 0
        decompiler_output = ida_hexrays.decompile(idaapi.get_screen_ea())
        v = ida_hexrays.get_widget_vdui(ctx.widget)
        # 中文
        query_model_async("查找下面这个C语言伪代码函数的漏洞并提出可能的利用方法。（用简体中文回答我，并且回答开始前加上'---GPT_VulnFinder_START---'字符串结束后加上'---GPT_VulnFinder_END---'字符串）\n"
                + str(decompiler_output),
                functools.partial(comment_callback, address=idaapi.get_screen_ea(), view=v, cmtFlag=0, printFlag=2),
                0)
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


# ReverseLLM 尝试对漏洞函数生成EXP
class expCreateHandler(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        funcComment = getFuncComment(idaapi.get_screen_ea())
        if "---GPT_VulnPython_START---" in funcComment:
            print("当前函数已经完成过 %s:ExpCreater 分析，请查看注释或删除注释重新分析。@小火车yyds"%(PLUGIN_NAME))
            return 0
        decompiler_output = ida_hexrays.decompile(idaapi.get_screen_ea())
        v = ida_hexrays.get_widget_vdui(ctx.widget)
        # 中文
        query_model_async("使用Python构造代码来利用下面函数中的漏洞。（用简体中文回答我，并且回答开始前加上'---GPT_VulnPython_START---'字符串结束后加上'---GPT_VulnPython_END---'字符串）\n"
                + str(decompiler_output),
                functools.partial(comment_callback, address=idaapi.get_screen_ea(), view=v, cmtFlag=0, printFlag=3),
                0)
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


def autoChatFunc(funcTree:str, strings:str, callback):
    messages = []
    input_funcTree = funcTree
    messages.append({"role": "user", "content": input_funcTree})
    input_strings = strings
    messages.append({"role": "user", "content": input_strings})
    messages.append({"role": "user", "content": "结合该程序的函数调用结构及其所包含的字符串，猜测其运行目的及功能。"})
    messages.append({"role": "user", "content": "请再仔细分析后告诉我该程序的运行目的及大概功能。"})
    t = threading.Thread(target=chat_api_worker, args=(messages, config.current_model, callback))
    t.start()


def chat_api_worker(messages, model, callback):
    try:
        response = config.client.chat.completions.create(messages=messages, model=model)
    except Exception as e:
        if "maximum context length" in str(e):
            print("此二进制文件的分析数据超过了 GPT-3.5-API 的最大长度！请期待后续版本 :)@小火车yyds")
            return 0
        elif "Cannot connect to proxy" in str(e):
            print("代理出现问题，请稍后重试或检查代理。@小火车yyds")
            return 0
        else:
            print(f"General exception encountered while running the query: {str(e)}")
            return 0
    callback(response)



# Gepetto query_model Method
def query_model(query, cb, max_tokens=2500):
    """
    向 gpt-3.5-turbo 发送查询的函数。
    :param query: The request to send to gpt-3.5-turbo
    :param cb: Tu function to which the response will be passed to.
    """
    try:
        global config
        response = config.client.chat.completions.create(
            model=config.current_model,
            messages=[
                {"role": "user", "content": query}
            ]
        )
        ida_kernwin.execute_sync(functools.partial(cb, response=response.choices[0].message.content), ida_kernwin.MFF_WRITE)
    except openai.BadRequestError as e:
        # Context length exceeded. Determine the max number of tokens we can ask for and retry.
        m = re.search(r'maximum context length is (\d+) tokens, however you requested \d+ tokens \((\d+) in your '
                      r'prompt;', str(e))
        if not m:
            print(f"{config.display_name} could not complete the request: {str(e)}")
            return
        (hard_limit, prompt_tokens) = (int(m.group(1)), int(m.group(2)))
        max_tokens = hard_limit - prompt_tokens
        if max_tokens >= 750:
            print(f"{PLUGIN_NAME}-Warning: Context length too long! Try reducing tokens to {max_tokens}...")
            print("Request to %s sent retried..."%(config.display_name))
            query_model(query, cb, max_tokens)
        else:
            print(f"Unfortunately, this function is too large to be analyzed using {config.display_name} API. @小火车yyds")
    except openai.OpenAIError as e:
        if "That model is currently overloaded with other requests" in str(e) or "Request timed out" in str(e):
            print(f"{config.display_name} API 繁忙，请稍后重试或检查代理。@小火车yyds")
        elif "Cannot connect to proxy" in str(e):
            print("代理出现问题，请稍后重试或检查代理。@小火车yyds")
        else:
            print(f"Server could not complete the request: {str(e)}")
            print(config.current_model)
    except Exception as e:
        print(f"General exception encountered while running the query: {str(e)}")


# Gepetto query_model_async Method
def query_model_async(query, cb, time):
    """
    创建线程调用 query_model 函数。
    :param query: The request to send to gpt-3.5-turbo
    :param cb: Tu function to which the response will be passed to.
    :param time: whether it is a retry.
    """
    if time == 0:
        print(f"正在发送 {config.display_name} API 请求，完成后将输出提示。@小火车yyds")
        print("Request to %s sent..."%(config.display_name))
    else:
        print(f"正在重新发送 {config.display_name} API 请求。@小火车yyds")
    t = threading.Thread(target=query_model, args=[query, cb])
    t.start()


# Gepetto comment_callback Method
def comment_callback(address, view, response, cmtFlag, printFlag):
    """
    在对应地址处设置注释的回调函数。
    :param address: The address of the function to comment
    :param view: A handle to the decompiler window
    :param response: The comment to add
    """
    # Add the response as a comment in IDA.
    # 通过参数控制不同形式添加注释
    if cmtFlag == 0:
        idc.set_func_cmt(address, response, 0)
    elif cmtFlag == 1:
        idc.set_cmt(address, response, 1)
    # Refresh the window so the comment is displayed properly
    if view:
        view.refresh_view(False)
    print("%s query finished!"%(config.display_name))
    if printFlag == 0:
        print("%s:Explain 完成分析，已对函数 %s 进行注释。@小火车yyds" %(PLUGIN_NAME, idc.get_func_name(address)))
        print("--------------------内容由 AI 生成，请仔细甄别--------------------")
    elif printFlag == 1:
        print("%s:Python 完成分析，已在函数末尾地址 %s 汇编处进行注释。@小火车yyds"%(PLUGIN_NAME, hex(address)))
        print("--------------------内容由 AI 生成，请仔细甄别--------------------")
    elif printFlag == 2:
        print("%s:VulnFinder 完成分析，已对函数 %s 进行注释。@小火车yyds" %(PLUGIN_NAME, idc.get_func_name(address)))
        print("--------------------内容由 AI 生成，请仔细甄别--------------------")
    elif printFlag == 3:
        print("%s:ExpCreater 完成分析，已对函数 %s 进行注释。@小火车yyds" %(PLUGIN_NAME, idc.get_func_name(address)))
        print("--------------------内容由 AI 生成，请仔细甄别--------------------")


# Gepetto rename_callback Method
def rename_callback(address, view, response, retries=0):
    """
    重命名函数变量的回调函数。
    :param address: The address of the function to work on
    :param view: A handle to the decompiler window
    :param response: The response from gpt-3.5-turbo
    :param retries: The number of times that we received invalid JSON
    """
    j = re.search(r"\{[^}]*?\}", response)
    if not j:
        if retries >= 3:  # Give up obtaining the JSON after 3 times.
            print(f"{config.display_name} API has no valid response, please try again later. @小火车yyds")
            return
        print(f"Cannot extract valid JSON from the response. Asking the model to fix it...")
        query_model_async("The JSON document provided in this response is invalid. Can you fix it?\n" + response,
                          functools.partial(rename_callback,
                                            address=address,
                                            view=view,
                                            retries=retries + 1), 
                                            1)
        return
    try:
        names = json.loads(j.group(0))
    except json.decoder.JSONDecodeError:
        if retries >= 3:  # Give up fixing the JSON after 3 times.
            print(f"{config.display_name} API has no valid response, please try again later. @小火车yyds")
            return
        print(f"The JSON document returned is invalid. Asking the model to fix it...")
        query_model_async("Please fix the following JSON document:\n" + j.group(0),
                          functools.partial(rename_callback,
                                            address=address,
                                            view=view,
                                            retries=retries + 1), 
                                            1)
        return
    # The rename function needs the start address of the function
    function_addr = idaapi.get_func(address).start_ea
    replaced = []
    for n in names:
        if ida_hexrays.rename_lvar(function_addr, n, names[n]):
            replaced.append(n)

    # Update possible names left in the function comment
    comment = idc.get_func_cmt(address, 0)
    if comment and len(replaced) > 0:
        for n in replaced:
            comment = re.sub(r'\b%s\b' % n, names[n], comment)
        idc.set_func_cmt(address, comment, 0)
    # Refresh the window to show the new names
    if view:
        view.refresh_view(True)
    print("%s query finished!"%(config.display_name))
    print(f"{PLUGIN_NAME}:RenameVariable 完成分析，已重命名{len(replaced)}个变量。@小火车yyds")

# 获取函数注释
def getFuncComment(address):
    cmt = idc.get_func_cmt(address, 0)
    if not cmt:
        cmt = idc.get_func_cmt(address, 1)
    return cmt


# 获取地址注释
def getAddrComment(address):
    cmt = idc.get_cmt(address, 0)
    if not cmt:
        cmt = idc.get_cmt(address, 1)
    return cmt


# Add context menu actions
class ContextMenuHooks(idaapi.UI_Hooks):
    def finish_populating_widget_popup(self, form, popup):
        idaapi.attach_action_to_popup(form, popup, myplugin_ReverseLLM.explain_action_name, "%s/"%(PLUGIN_NAME))
        idaapi.attach_action_to_popup(form, popup, myplugin_ReverseLLM.rename_action_name, "%s/"%(PLUGIN_NAME))
        idaapi.attach_action_to_popup(form, popup, myplugin_ReverseLLM.python_action_name, "%s/"%(PLUGIN_NAME))
        idaapi.attach_action_to_popup(form, popup, myplugin_ReverseLLM.vulnFinder_action_name, "%s/"%(PLUGIN_NAME))
        idaapi.attach_action_to_popup(form, popup, myplugin_ReverseLLM.expPython_action_name, "%s/"%(PLUGIN_NAME))
        for model_name, model in config.models.items():
            action_name = f"switch_{model_name}"
            display_name = model.get('display_name', model_name)
            idaapi.attach_action_to_popup(
                form, 
                popup, 
                action_name, 
                f"{PLUGIN_NAME}/切换模型/"
            )
def add_model_switches(cls):
    """为类添加模型切换相关的变量"""
    for model_name, model_config in config.models.items():
        # 添加 action name 变量
        setattr(cls, f"switch_{model_name}_action_name", f"switch_{model_name}")
        # 添加 menu path 变量
        setattr(cls, f"switch_{model_name}_menu_path", f"Edit/{PLUGIN_NAME}/切换模型/")
    return cls

@add_model_switches
class myplugin_ReverseLLM(idaapi.plugin_t):
    explain_action_name = "%s:Explain_Function"%(PLUGIN_NAME)
    explain_menu_path = "Edit/%s/函数分析"%(PLUGIN_NAME)
    rename_action_name = "%s:Rename_Function"%(PLUGIN_NAME)
    rename_menu_path = "Edit/%s/重命名函数变量"%(PLUGIN_NAME)
    python_action_name = "%s:Python_Function"%(PLUGIN_NAME)
    python_menu_path = "Edit/%s/Python还原此函数"%(PLUGIN_NAME)
    vulnFinder_action_name = "%s:VulnFinder_Function"%(PLUGIN_NAME)
    vulnFinder_menu_path = "Edit/%s/二进制漏洞查找"%(PLUGIN_NAME)
    expPython_action_name = "%s:VulnPython_Function"%(PLUGIN_NAME)
    expPython_menu_path = "Edit/%s/尝试生成Exploit"%(PLUGIN_NAME)

    wanted_name = PLUGIN_NAME
    wanted_hotkey = ''
    comment = "%s Plugin for IDA"%(PLUGIN_NAME)
    help = "Find more information at https://github.com/wpeace-hch"
    menu = None
    flags = 0
    def init(self):
        # Check whether the decompiler is available
        if not ida_hexrays.init_hexrays_plugin():
            return idaapi.PLUGIN_SKIP
        # Function explaining action
        explain_action = idaapi.action_desc_t(self.explain_action_name,
                                                '函数分析',
                                                ExplainHandler(),
                                                "Ctrl+Alt+G",
                                                "使用 %s 分析当前函数"%(config.current_model),
                                                199)
        idaapi.register_action(explain_action)
        idaapi.attach_action_to_menu(self.explain_menu_path, self.explain_action_name, idaapi.SETMENU_APP)
        # Variable renaming action
        rename_action = idaapi.action_desc_t(self.rename_action_name,
                                                '重命名函数变量',
                                                RenameHandler(),
                                                "Ctrl+Alt+R",
                                                "使用 %s 重命名当前函数的变量"%(config.current_model),
                                                199)
        idaapi.register_action(rename_action)
        idaapi.attach_action_to_menu(self.rename_menu_path, self.rename_action_name, idaapi.SETMENU_APP)
        # python function action
        python_action = idaapi.action_desc_t(self.python_action_name,
                                                'Python还原此函数',
                                                PythonHandler(),
                                                "",
                                                "使用 %s 分析当前函数并用python3还原"%(config.current_model),
                                                199)
        idaapi.register_action(python_action)
        idaapi.attach_action_to_menu(self.python_menu_path, self.python_action_name, idaapi.SETMENU_APP)
        # find vulnerabilty action
        vulnFinder_action = idaapi.action_desc_t(self.vulnFinder_action_name,
                                                '二进制漏洞查找',
                                                FindVulnHandler(),
                                                "Ctrl+Alt+E",
                                                "使用 %s 在当前函数中查找漏洞"%(config.current_model),
                                                199)
        idaapi.register_action(vulnFinder_action)
        idaapi.attach_action_to_menu(self.vulnFinder_menu_path, self.vulnFinder_action_name, idaapi.SETMENU_APP)
        # create exploit action
        expPython_action = idaapi.action_desc_t(self.expPython_action_name,
                                                '尝试生成Exploit',
                                                expCreateHandler(),
                                                "",
                                                "使用 %s 尝试对漏洞函数生成EXP"%(config.current_model),
                                                199)
        idaapi.register_action(expPython_action)
        idaapi.attach_action_to_menu(self.expPython_menu_path, self.expPython_action_name, idaapi.SETMENU_APP)

        for model_name, model_config in config.models.items():
            action = idaapi.action_desc_t(
                getattr(self, f"switch_{model_name}_action_name"),  # 使用之前生成的类变量
                f"{model_name}",
                SwitchModelHandler(model_name),  # 使用统一的 Handler
                "",
                f"使用 {model_config['display_name']}",
                199
            )
            idaapi.register_action(action)
            idaapi.attach_action_to_menu(
                getattr(self, f"switch_{model_name}_menu_path"),
                getattr(self, f"switch_{model_name}_action_name"),
                idaapi.SETMENU_APP
            )

        # Register context menu actions
        self.menu = ContextMenuHooks()
        self.menu.hook()
        print("ReverseLLM auto-analyze v0.1 is ready.")
        print("%s v1.0 works fine! :)@小火车yyds\n"%(PLUGIN_NAME))
        print(f"默认使用的模型为：{config.display_name}")
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        pass

    def term(self):
        idaapi.detach_action_from_menu(self.explain_menu_path, self.explain_action_name)
        idaapi.detach_action_from_menu(self.rename_menu_path, self.rename_action_name)
        idaapi.detach_action_from_menu(self.python_menu_path, self.python_action_name)
        idaapi.detach_action_from_menu(self.vulnFinder_menu_path, self.vulnFinder_action_name)
        idaapi.detach_action_from_menu(self.expPython_menu_path, self.expPython_action_name)
        for model_name, model_config in config.models.items():
            idaapi.detach_action_from_menu(getattr(self, f"switch_{model_name}_menu_path"), getattr(self, f"switch_{model_name}_action_name"))

        if self.menu:
            self.menu.unhook()
        return  

def PLUGIN_ENTRY():
    return type(f"myplugin_{PLUGIN_NAME}", (myplugin_ReverseLLM, ), dict())()