import ctypes, ctypes.wintypes as w, os, sys, struct, subprocess, threading, time, json, argparse, queue, base64
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import numpy as np

DEV = base64.b64decode('XFwuXEdMT0JBTFJPT1RcRGV2aWNlXFduU3ZjNkIyRA==').decode()
IOCTL_READ = 0x00222000
IOCTL_WRITE = 0x00222004
IOCTL_MODULE = 0x00222008
IOCTL_INFO = 0x0022200C
IOCTL_HIDE_DEVICE = 0x00222014
SCAN_CHUNK = 0x100000
PAGE = 0x1000

k32 = ctypes.WinDLL('kernel32', use_last_error=True)
k32.CreateFileW.restype = w.HANDLE
k32.CreateFileW.argtypes = [w.LPCWSTR, w.DWORD, w.DWORD, w.LPVOID, w.DWORD, w.DWORD, w.HANDLE]
k32.DeviceIoControl.argtypes = [w.HANDLE, w.DWORD, w.LPVOID, w.DWORD, w.LPVOID, w.DWORD,
                                ctypes.POINTER(w.DWORD), w.LPVOID]
k32.DeviceIoControl.restype = w.BOOL
k32.OpenProcess.restype = w.HANDLE
k32.OpenProcess.argtypes = [w.DWORD, w.BOOL, w.DWORD]
k32.VirtualQueryEx.argtypes = [w.HANDLE, w.LPCVOID, w.LPVOID, ctypes.c_size_t]
k32.VirtualQueryEx.restype = ctypes.c_size_t
k32.CreateToolhelp32Snapshot.restype = w.HANDLE
k32.CreateToolhelp32Snapshot.argtypes = [w.DWORD, w.DWORD]

class TS_MEM_REQ(ctypes.Structure):
    _fields_ = [('pid', w.DWORD), ('size', w.DWORD), ('addr', ctypes.c_ulonglong),
                ('flags', w.DWORD), ('reserved', w.DWORD)]

class TS_MODULE_REQ(ctypes.Structure):
    _fields_ = [('pid', w.DWORD), ('reserved', w.DWORD), ('name', w.WCHAR * 64)]

class TS_MODULE_RSP(ctypes.Structure):
    _fields_ = [('base', ctypes.c_ulonglong), ('size', w.DWORD), ('reserved', w.DWORD),
                ('path', w.WCHAR * 260)]

class MBI(ctypes.Structure):
    _fields_ = [('BaseAddress', ctypes.c_void_p), ('AllocationBase', ctypes.c_void_p),
                ('AllocationProtect', w.DWORD), ('RegionSize', ctypes.c_size_t),
                ('State', w.DWORD), ('Protect', w.DWORD), ('Type', w.DWORD)]

class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [('dwSize', w.DWORD), ('cntUsage', w.DWORD), ('th32ProcessID', w.DWORD),
                ('th32DefaultHeapID', ctypes.c_size_t), ('th32ModuleID', w.DWORD),
                ('cntThreads', w.DWORD), ('th32ParentProcessID', w.DWORD),
                ('pcPriClassBase', w.LONG), ('dwFlags', w.DWORD), ('szExeFile', w.WCHAR * 260)]

def list_processes():
    snap = k32.CreateToolhelp32Snapshot(0x2, 0)
    if snap in (-1, w.HANDLE(-1).value):
        return []
    pe = PROCESSENTRY32W()
    pe.dwSize = ctypes.sizeof(pe)
    out = []
    if k32.Process32FirstW(snap, ctypes.byref(pe)):
        while True:
            out.append((pe.th32ProcessID, pe.szExeFile))
            if not k32.Process32NextW(snap, ctypes.byref(pe)):
                break
    k32.CloseHandle(snap)
    return out

def enum_regions(pid):
    hproc = k32.OpenProcess(0x400, False, pid)
    if not hproc:
        hproc = k32.OpenProcess(0x1000, False, pid)
    if not hproc:
        return []
    out = []
    addr = 0x10000
    while addr < 0x7FFF0000:
        mbi = MBI()
        if not k32.VirtualQueryEx(hproc, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)):
            break
        base = mbi.BaseAddress or 0
        size = mbi.RegionSize or 0
        if size == 0:
            break
        if mbi.State == 0x1000 and mbi.Protect not in (0, 1) and not (mbi.Protect & 0x100) and (mbi.Protect & 0xCC):
            out.append((base, size))
        addr = base + size
    k32.CloseHandle(hproc)
    return out

class Driver:
    def __init__(self, path=DEV):
        self.path = path
        self.h = None

    def open(self):
        self.h = k32.CreateFileW(self.path, 0x80000000 | 0x40000000, 0, None, 3, 0, None)
        if self.h in (-1, w.HANDLE(-1).value):
            self.h = None
            raise OSError(ctypes.get_last_error(), f'open {self.path}')

    def close(self):
        if self.h:
            k32.CloseHandle(self.h)
            self.h = None

    def read(self, pid, addr, size):
        req = TS_MEM_REQ(pid, size, addr, 0, 0)
        out = ctypes.create_string_buffer(size)
        ret = w.DWORD(0)
        ok = k32.DeviceIoControl(self.h, IOCTL_READ, ctypes.byref(req), ctypes.sizeof(req),
                                 out, size, ctypes.byref(ret), None)
        if not ok:
            raise OSError(ctypes.get_last_error())
        return out.raw[:ret.value]

    def write(self, pid, addr, data):
        req = TS_MEM_REQ(pid, len(data), addr, 0, 0)
        buf = ctypes.create_string_buffer(ctypes.sizeof(req) + len(data))
        ctypes.memmove(buf, ctypes.byref(req), ctypes.sizeof(req))
        ctypes.memmove(ctypes.addressof(buf) + ctypes.sizeof(req), data, len(data))
        ret = w.DWORD(0)
        ok = k32.DeviceIoControl(self.h, IOCTL_WRITE, buf, ctypes.sizeof(buf), None, 0,
                                 ctypes.byref(ret), None)
        if not ok:
            raise OSError(ctypes.get_last_error())

    def module(self, pid, name):
        req = TS_MODULE_REQ(pid, 0, name[:63])
        rsp = TS_MODULE_RSP()
        ret = w.DWORD(0)
        ok = k32.DeviceIoControl(self.h, IOCTL_MODULE, ctypes.byref(req), ctypes.sizeof(req),
                                 ctypes.byref(rsp), ctypes.sizeof(rsp), ctypes.byref(ret), None)
        if not ok:
            raise OSError(ctypes.get_last_error())
        return rsp.base, rsp.size, rsp.path

    def hide_device(self):
        ret = w.DWORD(0)
        ok = k32.DeviceIoControl(self.h, IOCTL_HIDE_DEVICE, None, 0, None, 0,
                                 ctypes.byref(ret), None)
        if not ok:
            raise OSError(ctypes.get_last_error())

def dtype_of(vtype):
    return {'i32': np.uint32, 'i64': np.uint64, 'f32': np.float32, 'f64': np.float64}[vtype]

def width_of(vtype):
    return {'i32': 4, 'i64': 8, 'f32': 4, 'f64': 8}[vtype]

def parse_value(text, vtype):
    text = text.strip().replace(',', '')
    if vtype in ('f32', 'f64'):
        return float(text)
    return int(text, 0)

def fmt_value(v, vtype):
    if vtype in ('f32', 'f64'):
        return f'{v:.6f}'
    return str(v)

def scan_value(driver, pid, vtype, value=None, lo=None, hi=None):
    dtype = dtype_of(vtype)
    width = width_of(vtype)
    results = []
    for base, size in enum_regions(pid):
        off = 0
        while off < size:
            n = min(SCAN_CHUNK, size - off)
            try:
                data = driver.read(pid, base + off, n)
            except OSError:
                off += n
                continue
            cut = len(data) - (len(data) % width)
            arr = np.frombuffer(data[:cut], dtype=dtype)
            if value is not None:
                if vtype in ('f32', 'f64'):
                    m = np.isclose(arr.astype(np.float64), float(value), rtol=0, atol=1e-4)
                else:
                    m = arr == value
            else:
                m = (arr >= lo) & (arr <= hi)
            for i in np.nonzero(m)[0]:
                results.append((base + off + int(i) * width, float(arr[i]) if vtype in ('f32', 'f64') else int(arr[i])))
            off += n
    return results

def filter_results(driver, pid, results, vtype, mode, target=None):
    width = width_of(vtype)
    dtype = dtype_of(vtype)
    pages = {}
    for addr, old in results:
        pages.setdefault(addr & ~(PAGE - 1), []).append((addr, old))
    kept = []
    for page, items in pages.items():
        try:
            data = driver.read(pid, page, PAGE)
        except OSError:
            continue
        for addr, old in items:
            off = addr - page
            if off + width > len(data):
                continue
            new = dtype = np.frombuffer(data[off:off+width], dtype=dtype_of(vtype))[0].item()
            ok = False
            if mode == 'exact':
                if vtype in ('f32', 'f64'):
                    ok = abs(new - float(target)) <= 1e-4
                else:
                    ok = new == target
            elif mode == 'increased':
                ok = new > old
            elif mode == 'decreased':
                ok = new < old
            elif mode == 'changed':
                ok = new != old
            elif mode == 'unchanged':
                ok = new == old
            if ok:
                kept.append((addr, new, old))
    return kept

class App:
    def __init__(self, root):
        self.root = root
        self.driver = Driver()
        self.connected = False
        self.pid = 0
        self.vtype = 'i32'
        self.results = []
        self.row_map = {}
        self.busy = False
        self.lock_thread = None
        self.lock_stop = threading.Event()
        self.lock_addr = 0
        self.lock_target = 0
        self.lock_reverse = False
        self.q = queue.Queue()
        self.build_ui()
        self.try_connect()
        self.root.after(100, self.poll_queue)
        self.root.protocol('WM_DELETE_WINDOW', self.on_close)

    def build_ui(self):
        self.root.title('工具')
        self.root.geometry('1000x700')
        top = ttk.Frame(self.root, padding=6)
        top.pack(fill='x')
        ttk.Label(top, text='进程:').pack(side='left')
        self.proc_var = tk.StringVar()
        self.proc_box = ttk.Combobox(top, textvariable=self.proc_var, width=40, state='readonly')
        self.proc_box.pack(side='left', padx=4)
        ttk.Button(top, text='刷新进程', command=self.refresh_procs).pack(side='left', padx=2)
        ttk.Button(top, text='连接驱动', command=self.try_connect).pack(side='left', padx=2)
        ttk.Button(top, text='隐藏设备', command=self.hide_device).pack(side='left', padx=2)
        self.drv_label = ttk.Label(top, text='驱动: 未连接')
        self.drv_label.pack(side='left', padx=12)

        scan = ttk.LabelFrame(self.root, text='扫描', padding=6)
        scan.pack(fill='x', padx=6, pady=4)
        ttk.Label(scan, text='类型:').grid(row=0, column=0, sticky='w')
        self.type_var = tk.StringVar(value='i32')
        ttk.Combobox(scan, textvariable=self.type_var, values=['i32', 'i64', 'f32', 'f64'],
                     width=8, state='readonly').grid(row=0, column=1, padx=4)
        ttk.Label(scan, text='值:').grid(row=0, column=2, sticky='w')
        self.value_var = tk.StringVar()
        ttk.Entry(scan, textvariable=self.value_var, width=18).grid(row=0, column=3, padx=4)
        ttk.Label(scan, text='或区间:').grid(row=0, column=4, sticky='w')
        self.lo_var = tk.StringVar()
        self.hi_var = tk.StringVar()
        ttk.Entry(scan, textvariable=self.lo_var, width=10).grid(row=0, column=5, padx=2)
        ttk.Label(scan, text='~').grid(row=0, column=6)
        ttk.Entry(scan, textvariable=self.hi_var, width=10).grid(row=0, column=7, padx=2)
        ttk.Button(scan, text='首次扫描', command=self.first_scan).grid(row=0, column=8, padx=8)

        filt = ttk.LabelFrame(self.root, text='再次扫描', padding=6)
        filt.pack(fill='x', padx=6, pady=4)
        ttk.Label(filt, text='条件:').pack(side='left')
        self.mode_var = tk.StringVar(value='exact')
        ttk.Combobox(filt, textvariable=self.mode_var,
                     values=['exact', 'increased', 'decreased', 'changed', 'unchanged'],
                     width=12, state='readonly').pack(side='left', padx=4)
        ttk.Label(filt, text='目标值(精确时):').pack(side='left')
        self.target_var = tk.StringVar()
        ttk.Entry(filt, textvariable=self.target_var, width=16).pack(side='left', padx=4)
        ttk.Button(filt, text='再次扫描', command=self.next_scan).pack(side='left', padx=8)
        self.count_label = ttk.Label(filt, text='结果: 0')
        self.count_label.pack(side='left', padx=12)

        cols = ('addr', 'value', 'prev')
        self.tree = ttk.Treeview(self.root, columns=cols, show='headings', height=22)
        self.tree.heading('addr', text='地址')
        self.tree.heading('value', text='当前值')
        self.tree.heading('prev', text='上次值')
        self.tree.column('addr', width=160, anchor='w')
        self.tree.column('value', width=160, anchor='w')
        self.tree.column('prev', width=160, anchor='w')
        self.tree.pack(fill='both', expand=True, padx=6, pady=4)
        self.tree.bind('<<TreeviewSelect>>', self.on_select)

        bottom = ttk.Frame(self.root, padding=6)
        bottom.pack(fill='x')
        ttk.Label(bottom, text='写入值:').pack(side='left')
        self.write_var = tk.StringVar()
        ttk.Entry(bottom, textvariable=self.write_var, width=20).pack(side='left', padx=4)
        ttk.Button(bottom, text='写入选中地址', command=self.write_selected).pack(side='left', padx=4)
        self.reverse_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(bottom, text='反增', variable=self.reverse_var).pack(side='left', padx=4)
        ttk.Button(bottom, text='锁定数值(不减)', command=self.start_lock).pack(side='left', padx=4)
        ttk.Button(bottom, text='停止锁定', command=self.stop_lock).pack(side='left', padx=4)
        self.lock_label = ttk.Label(bottom, text='未锁定')
        self.lock_label.pack(side='left', padx=8)
        ttk.Button(bottom, text='添加地址', command=self.add_address).pack(side='left', padx=4)
        ttk.Button(bottom, text='模块基址', command=self.module_info).pack(side='left', padx=12)
        self.status = ttk.Label(self.root, text='就绪', relief='sunken', anchor='w')
        self.status.pack(fill='x', side='bottom')

    def set_status(self, text):
        self.status.config(text=text)

    def poll_queue(self):
        try:
            while True:
                msg = self.q.get_nowait()
                kind = msg[0]
                if kind == 'first':
                    self.finish_first(msg[1], msg[2])
                elif kind == 'next':
                    self.finish_next(msg[1])
                elif kind == 'fail':
                    self.fail(msg[1])
        except queue.Empty:
            pass
        self.root.after(100, self.poll_queue)

    def try_connect(self):
        try:
            self.driver.close()
            self.driver.open()
            self.connected = True
            self.drv_label.config(text='驱动: 已连接')
            self.refresh_procs()
        except OSError as e:
            self.connected = False
            self.drv_label.config(text='驱动: 未连接')
            messagebox.showerror('未连接',
                                 '请先加载驱动。')

    def hide_device(self):
        if not self.connected:
            messagebox.showwarning('未连接', '驱动未连接')
            return
        if not messagebox.askyesno('隐藏设备',
                                   '隐藏后本次会话不能再重新打开设备；\n'
                                   '重开工具需要重新映射驱动。继续？'):
            return
        try:
            self.driver.hide_device()
            self.set_status('设备已隐藏')
            messagebox.showinfo('完成', '设备名已从内核命名空间移除；当前句柄仍可读写。')
        except OSError as e:
            messagebox.showerror('失败', str(e))

    def refresh_procs(self):
        procs = list_processes()
        items = [f'{name} ({pid})' for pid, name in sorted(procs, key=lambda x: x[1].lower())]
        self.proc_box['values'] = items
        if not self.proc_var.get() and items:
            for it in items:
                if it.lower().startswith('dmmdzz.exe'):
                    self.proc_var.set(it)
                    break
            else:
                self.proc_var.set(items[0])

    def current_pid(self):
        s = self.proc_var.get()
        if not s:
            return 0
        try:
            return int(s.rsplit('(', 1)[1].rstrip(')'))
        except Exception:
            return 0

    def first_scan(self):
        if self.busy:
            return
        if not self.connected:
            messagebox.showwarning('未连接', '驱动未连接')
            return
        pid = self.current_pid()
        if not pid:
            messagebox.showwarning('进程', '请选择进程')
            return
        vtype = self.type_var.get()
        text = self.value_var.get().strip()
        lo_text = self.lo_var.get().strip()
        hi_text = self.hi_var.get().strip()
        try:
            if text:
                value = parse_value(text, vtype)
                lo = hi = None
            elif lo_text and hi_text:
                value = None
                lo = parse_value(lo_text, vtype)
                hi = parse_value(hi_text, vtype)
            else:
                messagebox.showwarning('输入', '请输入值，或填写区间')
                return
        except Exception as e:
            messagebox.showerror('输入错误', str(e))
            return
        self.busy = True
        self.set_status('首次扫描中...')
        def work():
            try:
                res = scan_value(self.driver, pid, vtype, value, lo, hi)
                self.q.put(('first', res, vtype))
            except Exception as e:
                self.q.put(('fail', e))
        threading.Thread(target=work, daemon=True).start()

    def finish_first(self, res, vtype):
        try:
            self.results = res
            self.vtype = vtype
            self.populate(res)
            self.count_label.config(text=f'结果: {len(res)}')
            self.set_status(f'首次扫描完成: {len(res)} 个')
        except Exception as e:
            messagebox.showerror('显示结果失败', str(e))
        finally:
            self.busy = False

    def next_scan(self):
        if self.busy:
            return
        if not self.connected:
            messagebox.showwarning('未连接', '驱动未连接')
            return
        if not self.results:
            messagebox.showwarning('无结果', '先做首次扫描')
            return
        pid = self.current_pid()
        mode = self.mode_var.get()
        target = None
        if mode == 'exact':
            text = self.target_var.get().strip()
            if not text:
                messagebox.showwarning('目标值', '精确模式需要目标值')
                return
            try:
                target = parse_value(text, self.vtype)
            except Exception as e:
                messagebox.showerror('输入错误', str(e))
                return
        self.busy = True
        self.set_status('再次扫描中...')
        def work():
            try:
                kept = filter_results(self.driver, pid, self.results, self.vtype, mode, target)
                self.q.put(('next', kept))
            except Exception as e:
                self.q.put(('fail', e))
        threading.Thread(target=work, daemon=True).start()

    def finish_next(self, kept):
        try:
            self.results = [(a, n) for a, n, o in kept]
            self.populate(kept)
            self.count_label.config(text=f'结果: {len(kept)}')
            self.set_status(f'再次扫描完成: {len(kept)} 个')
        except Exception as e:
            messagebox.showerror('显示结果失败', str(e))
        finally:
            self.busy = False

    def populate(self, rows):
        self.tree.delete(*self.tree.get_children())
        self.row_map.clear()
        for row in rows[:1000]:
            if len(row) == 3:
                a, v, o = row
            else:
                a, v = row
                o = v
            iid = self.tree.insert('', 'end', values=(f'{a:08X}', fmt_value(v, self.vtype), fmt_value(o, self.vtype)))
            self.row_map[iid] = (a, v)

    def on_select(self, _event=None):
        sel = self.tree.selection()
        if sel:
            a, v = self.row_map.get(sel[0], (0, 0))
            self.write_var.set(fmt_value(v, self.vtype))

    def write_selected(self):
        if not self.connected:
            messagebox.showwarning('未连接', '驱动未连接')
            return
        sel = self.tree.selection()
        if not sel:
            messagebox.showwarning('选择', '先选中一行')
            return
        addr, old = self.row_map[sel[0]]
        text = self.write_var.get().strip()
        try:
            val = parse_value(text, self.vtype)
        except Exception as e:
            messagebox.showerror('输入错误', str(e))
            return
        if not messagebox.askyesno('确认写入', f'写入 {fmt_value(val, self.vtype)} 到 {addr:08X}？'):
            return
        try:
            if self.vtype == 'i32':
                data = struct.pack('<i', int(val))
            elif self.vtype == 'i64':
                data = struct.pack('<q', int(val))
            elif self.vtype == 'f32':
                data = struct.pack('<f', float(val))
            else:
                data = struct.pack('<d', float(val))
            self.driver.write(self.current_pid(), addr, data)
            self.tree.item(sel[0], values=(f'{addr:08X}', fmt_value(val, self.vtype), fmt_value(old, self.vtype)))
            if self.lock_thread is not None and self.lock_addr == addr:
                self.lock_target = val
            self.set_status(f'已写入 {addr:08X}')
        except OSError as e:
            messagebox.showerror('写入失败', str(e))

    def start_lock(self):
        if not self.connected:
            messagebox.showwarning('未连接', '驱动未连接')
            return
        sel = self.tree.selection()
        if not sel:
            messagebox.showwarning('选择', '先选中一行')
            return
        addr, old = self.row_map[sel[0]]
        text = self.write_var.get().strip()
        try:
            target = parse_value(text, self.vtype) if text else old
        except Exception as e:
            messagebox.showerror('输入错误', str(e))
            return
        if not messagebox.askyesno('锁定确认',
                                   f'锁定 {addr:08X} = {fmt_value(target, self.vtype)}？\n'
                                   '数值变小时会写回；勾选“反增”则每次减少会额外增加。'):
            return
        self.stop_lock()
        self.lock_stop = threading.Event()
        self.lock_addr = addr
        self.lock_target = target
        self.lock_reverse = bool(self.reverse_var.get())
        pid = self.current_pid()
        vtype = self.vtype

        def work():
            while not self.lock_stop.is_set():
                try:
                    raw = self.driver.read(pid, addr, width_of(vtype))
                    if vtype in ('i32', 'i64'):
                        cur = int.from_bytes(raw, 'little')
                    elif vtype == 'f32':
                        cur = struct.unpack('<f', raw)[0]
                    else:
                        cur = struct.unpack('<d', raw)[0]
                    if cur < self.lock_target:
                        new = self.lock_target + (self.lock_target - cur) if self.lock_reverse else self.lock_target
                        if vtype == 'i32':
                            data = struct.pack('<i', int(new))
                        elif vtype == 'i64':
                            data = struct.pack('<q', int(new))
                        elif vtype == 'f32':
                            data = struct.pack('<f', float(new))
                        else:
                            data = struct.pack('<d', float(new))
                        self.driver.write(pid, addr, data)
                        self.lock_target = new
                except OSError:
                    pass
                time.sleep(0.05)

        self.lock_thread = threading.Thread(target=work, daemon=True)
        self.lock_thread.start()
        suffix = ' 反增' if self.lock_reverse else ''
        self.lock_label.config(text=f'锁定中: {addr:08X} = {fmt_value(target, vtype)}{suffix}')
        self.set_status(f'已锁定 {addr:08X}')

    def stop_lock(self):
        if self.lock_thread is not None:
            self.lock_stop.set()
            self.lock_thread.join(timeout=0.5)
            self.lock_thread = None
        if hasattr(self, 'lock_label'):
            self.lock_label.config(text='未锁定')

    def add_address(self):
        if not self.connected:
            messagebox.showwarning('未连接', '驱动未连接')
            return
        text = simpledialog.askstring('添加地址', '十六进制地址（例如 4229F29C）')
        if not text:
            return
        try:
            addr = int(text.strip().lower().replace('0x', ''), 16)
        except Exception:
            messagebox.showerror('地址错误', '请输入十六进制地址')
            return
        try:
            raw = self.driver.read(self.current_pid(), addr, width_of(self.vtype))
            if self.vtype in ('i32', 'i64'):
                val = int.from_bytes(raw, 'little')
            elif self.vtype == 'f32':
                val = struct.unpack('<f', raw)[0]
            else:
                val = struct.unpack('<d', raw)[0]
        except OSError as e:
            messagebox.showerror('读取失败', str(e))
            return
        iid = self.tree.insert('', 0, values=(f'{addr:08X}', fmt_value(val, self.vtype), fmt_value(val, self.vtype)))
        self.row_map[iid] = (addr, val)
        self.tree.selection_set(iid)
        self.write_var.set(fmt_value(val, self.vtype))
        self.set_status(f'已添加 {addr:08X} = {fmt_value(val, self.vtype)}')

    def on_close(self):
        self.stop_lock()
        self.driver.close()
        self.root.destroy()

    def module_info(self):
        if not self.connected:
            messagebox.showwarning('未连接', '驱动未连接')
            return
        pid = self.current_pid()
        name = simpledialog.askstring('模块基址', '模块名（例如 GameAssembly.dll）', initialvalue='GameAssembly.dll')
        if not name:
            return
        try:
            base, size, path = self.driver.module(pid, name)
            messagebox.showinfo('模块基址', f'{name}\nbase = {base:08X}\nsize = {size:X}\npath = {path}')
        except OSError as e:
            messagebox.showerror('查询失败', str(e))

    def fail(self, e):
        self.busy = False
        self.set_status('失败')
        messagebox.showerror('错误', str(e))

def selftest():
    d = Driver()
    d.open()
    print('[+] driver', DEV)
    procs = list_processes()
    pid = next((p for p, n in procs if n.lower() == 'dmmdzz.exe'), 0)
    print('[+] pid', pid)
    res = scan_value(d, pid, 'i32', 100)
    print('[+] scan 100 hits', len(res))
    time.sleep(2)
    kept = filter_results(d, pid, res, 'i32', 'increased')
    print('[+] increased after 2s', len(kept))
    for a, n, o in kept[:10]:
        print(f'    {a:08X}: {o} -> {n}')
    d.close()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--selftest', action='store_true')
    args = ap.parse_args()
    if args.selftest:
        selftest()
        return
    root = tk.Tk()
    App(root)
    root.mainloop()

if __name__ == '__main__':
    main()
