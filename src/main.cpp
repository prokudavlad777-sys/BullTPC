// BullTPC: оптимізатор інтернету (Win32, C++17)
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#include <windns.h>
#include <winhttp.h>
#include <dwmapi.h>
#include <string>
#include <vector>
#include <deque>
#include <thread>
#include <mutex>
#include <atomic>
#include <algorithm>
#include <cmath>
#include <cstring>
using std::wstring;

static const int W = 1000, H = 640;
static const COLORREF BG = RGB(20, 18, 30), PAN = RGB(30, 28, 44), CARD = RGB(41, 39, 64), ACC = RGB(109, 94, 240),
    TX = RGB(236, 234, 255), MU = RGB(154, 151, 184), OK = RGB(74, 222, 128), WN = RGB(251, 191, 36), ER = RGB(248, 113, 113);

struct Srv { const wchar_t* n; const char *a, *b; };
static const Srv SRV[] = {{L"Cloudflare", "1.1.1.1", "1.0.0.1"}, {L"Google", "8.8.8.8", "8.8.4.4"},
                          {L"Quad9", "9.9.9.9", "149.112.112.112"}, {L"OpenDNS", "208.67.222.222", "208.67.220.220"}};
static const wchar_t* TABS[] = {L"DNS Optimizer", L"TCP Optimizer", L"Internet Problem Detector", L"Live Ping"};
static const wchar_t* OPTN[] = {L"Автонастроювання вікна TCP", L"RSS: обробка на кількох ядрах", L"ECN (деякі роутери з ним гірші)",
                                L"Вимкнути мітки часу TCP", L"Початковий RTO 2000 мс"};
static const wchar_t* OPTC[] = {L"autotuninglevel=normal", L"rss=enabled", L"ecncapability=enabled", L"timestamps=disabled", L"initialRto=2000"};
static const char* PT[] = {"1.1.1.1", "8.8.8.8", "9.9.9.9"};

struct Row { wstring t; int st; double v; };
static HWND hw; static int tab = 0, bestDns = -1, pT = 0;
static std::mutex mu; static std::atomic<bool> busy{false}, pingRun{false}; static std::atomic<int> gen{0};
static std::vector<Row> dnsR, detR; static wstring note; static bool opt[5] = {1, 1, 0, 1, 1};
static std::deque<double> hist; static std::vector<std::pair<RECT, int>> btns;
static HFONT fN, fB, fH, fM; static HICON ico;

static void post() { PostMessageW(hw, WM_APP, 0, 0); }
static void setNote(const wstring& s) { std::lock_guard<std::mutex> l(mu); note = s; }

static double dnsMs(const char* ip, const wchar_t* d) {
    IP4_ARRAY a; a.AddrCount = 1; if (ip) a.AddrArray[0] = inet_addr(ip);
    PDNS_RECORD r = nullptr; LARGE_INTEGER f, s, e; QueryPerformanceFrequency(&f); QueryPerformanceCounter(&s);
    DNS_STATUS st = DnsQuery_W(d, DNS_TYPE_A, DNS_QUERY_BYPASS_CACHE | DNS_QUERY_NO_HOSTS_FILE, ip ? &a : nullptr, &r, nullptr);
    QueryPerformanceCounter(&e); if (r) DnsRecordListFree(r, DnsFreeRecordList);
    return st ? -1 : (e.QuadPart - s.QuadPart) * 1000.0 / f.QuadPart;
}
static double pingMs(const char* ip) {
    HANDLE h = IcmpCreateFile(); if (h == INVALID_HANDLE_VALUE) return -1;
    char d[32] = {0}, buf[sizeof(ICMP_ECHO_REPLY) + 64]; double r = -1;
    DWORD n = IcmpSendEcho(h, inet_addr(ip), d, 32, nullptr, buf, sizeof buf, 2000);
    if (n && ((ICMP_ECHO_REPLY*)buf)->Status == IP_SUCCESS) r = ((ICMP_ECHO_REPLY*)buf)->RoundTripTime;
    IcmpCloseHandle(h); return r;
}
static bool site(const wchar_t* host) {
    HINTERNET s = WinHttpOpen(L"BullTPC", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, nullptr, nullptr, 0); if (!s) return false;
    WinHttpSetTimeouts(s, 3000, 3000, 3000, 3000); bool ok = false;
    if (HINTERNET c = WinHttpConnect(s, host, INTERNET_DEFAULT_HTTPS_PORT, 0)) {
        if (HINTERNET r = WinHttpOpenRequest(c, L"HEAD", L"/", nullptr, nullptr, nullptr, WINHTTP_FLAG_SECURE)) {
            ok = WinHttpSendRequest(r, nullptr, 0, nullptr, 0, 0, 0) && WinHttpReceiveResponse(r, nullptr); WinHttpCloseHandle(r);
        }
        WinHttpCloseHandle(c);
    }
    WinHttpCloseHandle(s); return ok;
}
static void run(const wstring& c) {
    wstring x = L"cmd /c " + c; STARTUPINFOW si{}; si.cb = sizeof si; si.dwFlags = STARTF_USESHOWWINDOW; si.wShowWindow = SW_HIDE; PROCESS_INFORMATION pi{};
    if (CreateProcessW(nullptr, &x[0], nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 30000); CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    }
}

static void dnsTest() {
    if (busy.exchange(true)) return;
    { std::lock_guard<std::mutex> l(mu); dnsR.clear(); bestDns = -1; note = L"Тестую DNS..."; } post();
    const wchar_t* D[] = {L"google.com", L"youtube.com", L"github.com", L"wikipedia.org", L"microsoft.com"};
    for (int i = 0; i < 4; i++) {
        std::vector<double> t; for (auto d : D) { double m = dnsMs(SRV[i].a, d); if (m >= 0) t.push_back(m); }
        std::sort(t.begin(), t.end()); double med = t.empty() ? -1 : t[t.size() / 2];
        { std::lock_guard<std::mutex> l(mu); dnsR.push_back({SRV[i].n, 0, med}); } post();
    }
    { std::lock_guard<std::mutex> l(mu); double b = 1e9;
      for (int i = 0; i < (int)dnsR.size(); i++) if (dnsR[i].v >= 0 && dnsR[i].v < b) { b = dnsR[i].v; bestDns = i; }
      note = bestDns >= 0 ? wstring(L"Найшвидший: ") + SRV[bestDns].n : L"Жоден DNS не відповів."; }
    busy = false; post();
}
static void dnsSet(int i) {  // i < 0: автоматичний DNS
    if (busy.exchange(true)) return;
    wstring ps = L"powershell -NoProfile -Command \"Get-NetAdapter | Where-Object Status -eq 'Up' | ForEach-Object { Set-DnsClientServerAddress -InterfaceIndex $_.ifIndex ";
    if (i < 0) ps += L"-ResetServerAddresses }\"";
    else { auto w = [](const char* s) { return wstring(s, s + strlen(s)); };
           ps += L"-ServerAddresses ('" + w(SRV[i].a) + L"','" + w(SRV[i].b) + L"') }\""; }
    setNote(L"Застосовую..."); post(); run(ps); run(L"ipconfig /flushdns");
    setNote(i < 0 ? L"DNS повернуто на автоматичний." : wstring(L"DNS змінено на ") + SRV[i].n + L"."); busy = false; post();
}
static void tcpApply(bool reset) {
    if (busy.exchange(true)) return; setNote(L"Застосовую..."); post();
    if (reset) run(L"netsh int tcp reset");
    else for (int i = 0; i < 5; i++) if (opt[i]) run(wstring(L"netsh int tcp set global ") + OPTC[i]);
    setNote(reset ? L"TCP повернуто до стандартних. Перезавантаж ПК." : L"Застосовано. Перезавантаж ПК для повного ефекту."); busy = false; post();
}
static void detect() {
    if (busy.exchange(true)) return; { std::lock_guard<std::mutex> l(mu); detR.clear(); note = L"Перевіряю..."; } post();
    auto add = [](int st, wstring s) { { std::lock_guard<std::mutex> l(mu); detR.push_back({s, st, 0}); } post(); };
    std::vector<double> g; for (int i = 0; i < 6; i++) { double p = pingMs("1.1.1.1"); if (p >= 0) g.push_back(p); Sleep(200); }
    if (g.empty()) { add(3, L"Немає відповіді від 1.1.1.1"); add(0, L"-> Перевір кабель, Wi-Fi, роутер і файрвол."); busy = false; setNote(L"Готово."); post(); return; }
    double sum = 0, mn = 1e9, mx = 0; for (double x : g) { sum += x; mn = std::min(mn, x); mx = std::max(mx, x); }
    double avg = sum / g.size(), jit = mx - mn; int lost = 6 - (int)g.size(); std::vector<wstring> adv;
    add(avg < 60 ? 1 : avg < 150 ? 2 : 3, L"Затримка: " + std::to_wstring((int)avg) + L" мс");
    if (avg >= 60) adv.push_back(L"Висока затримка: кабель замість Wi-Fi, закрий фонові завантаження.");
    add(lost == 0 ? 1 : lost < 2 ? 2 : 3, L"Втрати пакетів: " + std::to_wstring(lost * 100 / 6) + L"%");
    if (lost) adv.push_back(L"Є втрати пакетів: проблема з Wi-Fi, роутером або провайдером.");
    add(jit < 40 ? 1 : 2, L"Розкид затримки: " + std::to_wstring((int)jit) + L" мс");
    if (jit >= 40) adv.push_back(L"Нестабільна затримка: спробуй TCP Optimizer.");
    double sysd = dnsMs(nullptr, L"google.com"), cf = dnsMs("1.1.1.1", L"github.com");
    if (sysd < 0) { add(3, L"Системний DNS не відповідає"); adv.push_back(L"Змін DNS у вкладці DNS Optimizer."); }
    else { add(sysd < 100 ? 1 : 2, L"Системний DNS: " + std::to_wstring((int)sysd) + L" мс");
           if (cf >= 0 && sysd > cf + 30) adv.push_back(L"Публічний DNS швидший за твій: запусти DNS Optimizer."); }
    wstring bad; for (auto h : {L"www.google.com", L"github.com", L"www.wikipedia.org", L"www.cloudflare.com"}) if (!site(h)) bad += wstring(h) + L" ";
    add(bad.empty() ? 1 : 3, bad.empty() ? L"Тестові сайти відкриваються" : L"Не відкрились: " + bad);
    if (!bad.empty()) adv.push_back(L"Перевір VPN, файрвол або блокування провайдера.");
    if (adv.empty()) add(1, L"Проблем не знайдено."); for (auto& a : adv) add(0, L"-> " + a);
    busy = false; setNote(L"Готово."); post();
}
static void pingLoop(int g) {
    while (pingRun && gen == g) {
        double v = pingMs(PT[pT]); { std::lock_guard<std::mutex> l(mu); hist.push_back(v); if (hist.size() > 60) hist.pop_front(); } post();
        for (int i = 0; i < 10 && pingRun && gen == g; i++) Sleep(100);
    }
}
static void pingStart() { gen++; { std::lock_guard<std::mutex> l(mu); hist.clear(); } pingRun = true; std::thread(pingLoop, (int)gen).detach(); }

static void paint(HDC dc) {
    HDC m = CreateCompatibleDC(dc); HBITMAP bm = CreateCompatibleBitmap(dc, W, H); HGDIOBJ old = SelectObject(m, bm); btns.clear(); SetBkMode(m, TRANSPARENT);
    auto box = [&](int x, int y, int w, int h, COLORREF c, int r) {
        HBRUSH b = CreateSolidBrush(c); HPEN p = CreatePen(PS_SOLID, 1, c); HGDIOBJ ob = SelectObject(m, b), op = SelectObject(m, p);
        RoundRect(m, x, y, x + w, y + h, r, r); SelectObject(m, ob); SelectObject(m, op); DeleteObject(b); DeleteObject(p); };
    auto txt = [&](int x, int y, const wstring& s, COLORREF c, HFONT f) { SelectObject(m, f); SetTextColor(m, c); TextOutW(m, x, y, s.c_str(), (int)s.size()); };
    auto btn = [&](int x, int y, int w, int id, const wstring& s, bool pri) {
        box(x, y, w, 42, pri ? ACC : RGB(52, 49, 78), 14); RECT r{x, y, x + w, y + 42}; SetTextColor(m, TX); SelectObject(m, fB);
        DrawTextW(m, s.c_str(), -1, &r, DT_CENTER | DT_VCENTER | DT_SINGLELINE); btns.push_back({r, id}); };
    RECT all{0, 0, W, H}; HBRUSH bg = CreateSolidBrush(BG); FillRect(m, &all, bg); DeleteObject(bg);
    box(0, 0, 230, H, PAN, 0); DrawIconEx(m, 18, 22, ico, 44, 44, 0, nullptr, DI_NORMAL); txt(72, 28, L"BullTPC", TX, fH);
    for (int i = 0; i < 4; i++) { if (i == tab) box(14, 100 + i * 52, 204, 44, ACC, 14); txt(30, 110 + i * 52, TABS[i], i == tab ? RGB(255, 255, 255) : MU, fB); btns.push_back({RECT{14, 100 + i * 52, 218, 144 + i * 52}, 100 + i}); }
    txt(260, 24, TABS[tab], TX, fH);
    const wchar_t* sub[] = {L"Який DNS найшвидший саме з твого інтернету.", L"Вибери налаштування й застосуй їх одним кліком.", L"Перевірка з’єднання, DNS і доступу до сайтів.", L"Затримка в реальному часі, оновлення щосекунди."};
    txt(262, 64, sub[tab], MU, fN);
    std::lock_guard<std::mutex> l(mu);
    if (tab == 0) {
        box(260, 100, 700, 230, CARD, 20); double mx = 1; for (auto& r : dnsR) mx = std::max(mx, r.v);
        if (dnsR.empty()) txt(284, 120, L"Натисни «Перевірити».", MU, fN);
        for (int i = 0; i < (int)dnsR.size(); i++) { int y = 122 + i * 48; txt(284, y, dnsR[i].n, TX, fB);
            box(420, y + 8, 380, 10, RGB(60, 57, 88), 10); if (dnsR[i].v >= 0) box(420, y + 8, std::max(12, (int)(dnsR[i].v / mx * 380)), 10, i == bestDns ? OK : RGB(168, 156, 255), 10);
            txt(830, y, dnsR[i].v < 0 ? L"немає" : std::to_wstring((int)dnsR[i].v) + L" мс", i == bestDns ? OK : TX, fN); }
        txt(262, 346, note, MU, fN); btn(260, 400, 170, 1, L"Перевірити", true); btn(440, 400, 250, 2, L"Застосувати найшвидший", false); btn(700, 400, 260, 3, L"Повернути автоматичний DNS", false);
    } else if (tab == 1) {
        box(260, 100, 700, 240, CARD, 20);
        for (int i = 0; i < 5; i++) { int y = 118 + i * 44; box(284, y, 24, 24, opt[i] ? ACC : RGB(60, 57, 88), 8); if (opt[i]) txt(290, y + 1, L"✓", RGB(255, 255, 255), fB);
            txt(324, y, OPTN[i], TX, fN); btns.push_back({RECT{270, y - 6, 940, y + 34}, 10 + i}); }
        txt(262, 356, note, MU, fN); btn(260, 400, 220, 4, L"Застосувати", true); btn(490, 400, 290, 5, L"Скинути до стандартних", false);
    } else if (tab == 2) {
        box(260, 100, 700, 340, CARD, 20); if (detR.empty()) txt(284, 120, L"Натисни «Знайти проблеми».", MU, fN);
        for (int i = 0; i < (int)detR.size() && i < 9; i++) { int y = 120 + i * 34; COLORREF c = detR[i].st == 1 ? OK : detR[i].st == 2 ? WN : detR[i].st == 3 ? ER : MU;
            if (detR[i].st) box(284, y + 5, 12, 12, c, 12); txt(308, y, detR[i].t, detR[i].st ? TX : MU, fN); }
        txt(262, 452, note, MU, fN); btn(260, 490, 220, 6, L"Знайти проблеми", true);
    } else {
        box(260, 100, 700, 200, CARD, 20); std::vector<POINT> pts; double mx = 50, sum = 0, mn = 1e9, mxv = 0, jit = 0, prev = -1; int ok = 0;
        for (double v : hist) if (v >= 0) mx = std::max(mx, v); mx *= 1.1;
        HPEN pr = CreatePen(PS_SOLID, 2, RGB(248, 113, 113)); HGDIOBJ op = SelectObject(m, pr);
        for (int i = 0; i < (int)hist.size(); i++) { int x = 284 + (int)(i * 650.0 / 59); double v = hist[i];
            if (v < 0) { MoveToEx(m, x, 120, nullptr); LineTo(m, x, 280); continue; }
            pts.push_back({x, 280 - (int)(v / mx * 150)}); sum += v; ok++; mn = std::min(mn, v); mxv = std::max(mxv, v); if (prev >= 0) jit += fabs(v - prev); prev = v; }
        SelectObject(m, op); DeleteObject(pr); HPEN pl = CreatePen(PS_SOLID, 3, RGB(168, 156, 255)); op = SelectObject(m, pl);
        if (pts.size() > 1) Polyline(m, pts.data(), (int)pts.size()); SelectObject(m, op); DeleteObject(pl);
        std::wstring lab[5] = {L"Зараз", L"Середній", L"Мін / макс", L"Джитер", L"Втрати"}, val[5];
        if (ok) { double now = hist.back(); val[0] = now < 0 ? L"немає" : std::to_wstring((int)now) + L" мс"; val[1] = std::to_wstring((int)(sum / ok)) + L" мс";
            val[2] = std::to_wstring((int)mn) + L" / " + std::to_wstring((int)mxv); val[3] = std::to_wstring(ok > 1 ? (int)(jit / (ok - 1)) : 0) + L" мс";
            val[4] = std::to_wstring((int)(hist.size() - ok) * 100 / (int)hist.size()) + L"%"; } else for (auto& v : val) v = L"–";
        for (int i = 0; i < 5; i++) { int x = 260 + i * 142; box(x, 316, 132, 76, CARD, 16); txt(x + 14, 326, lab[i], MU, fN); txt(x + 14, 352, val[i], TX, fM); }
        btn(260, 420, 200, 7, pingRun ? L"Зупинити" : L"Запустити", true); btn(470, 420, 220, 8, wstring(L"Ціль: ") + std::wstring(PT[pT], PT[pT] + strlen(PT[pT])), false);
    }
    BitBlt(dc, 0, 0, W, H, m, 0, 0, SRCCOPY); SelectObject(m, old); DeleteObject(bm); DeleteDC(m);
}

static LRESULT CALLBACK proc(HWND h, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_CREATE: { hw = h; BOOL d = TRUE; DwmSetWindowAttribute(h, 20, &d, sizeof d);
        fN = CreateFontW(-17, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, 0, L"Segoe UI");
        fB = CreateFontW(-17, 0, 0, 0, FW_SEMIBOLD, 0, 0, 0, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, 0, L"Segoe UI");
        fH = CreateFontW(-28, 0, 0, 0, FW_BOLD, 0, 0, 0, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, 0, L"Segoe UI");
        fM = CreateFontW(-24, 0, 0, 0, FW_BOLD, 0, 0, 0, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, 0, L"Segoe UI");
        ico = (HICON)LoadImageW(GetModuleHandleW(nullptr), MAKEINTRESOURCEW(1), IMAGE_ICON, 44, 44, 0); return 0; }
    case WM_PAINT: { PAINTSTRUCT ps; HDC dc = BeginPaint(h, &ps); paint(dc); EndPaint(h, &ps); return 0; }
    case WM_ERASEBKGND: return 1;
    case WM_APP: InvalidateRect(h, nullptr, FALSE); return 0;
    case WM_LBUTTONDOWN: { POINT p{(short)LOWORD(lp), (short)HIWORD(lp)};
        for (auto& b : btns) if (PtInRect(&b.first, p)) { int id = b.second;
            if (id >= 100) tab = id - 100; else if (id >= 10) opt[id - 10] = !opt[id - 10];
            else if (id == 1) std::thread(dnsTest).detach();
            else if (id == 2 && bestDns >= 0) std::thread(dnsSet, bestDns).detach();
            else if (id == 3) std::thread(dnsSet, -1).detach();
            else if (id == 4) std::thread(tcpApply, false).detach();
            else if (id == 5) std::thread(tcpApply, true).detach();
            else if (id == 6) std::thread(detect).detach();
            else if (id == 7) { if (pingRun) { pingRun = false; gen++; } else pingStart(); }
            else if (id == 8) { pT = (pT + 1) % 3; if (pingRun) pingStart(); else { std::lock_guard<std::mutex> l(mu); hist.clear(); } }
            InvalidateRect(h, nullptr, FALSE); break; }
        return 0; }
    case WM_DESTROY: pingRun = false; PostQuitMessage(0); return 0;
    }
    return DefWindowProcW(h, msg, wp, lp);
}

int WINAPI wWinMain(HINSTANCE hi, HINSTANCE, PWSTR, int show) {
    WSADATA wsa; WSAStartup(MAKEWORD(2, 2), &wsa);
    WNDCLASSW wc{}; wc.lpfnWndProc = proc; wc.hInstance = hi; wc.hCursor = LoadCursorW(nullptr, IDC_ARROW); wc.lpszClassName = L"BullTPC";
    wc.hIcon = (HICON)LoadImageW(hi, MAKEINTRESOURCEW(1), IMAGE_ICON, 32, 32, 0); RegisterClassW(&wc);
    DWORD st = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX; RECT r{0, 0, W, H}; AdjustWindowRect(&r, st, FALSE);
    int ww = r.right - r.left, wh = r.bottom - r.top;
    HWND w = CreateWindowW(L"BullTPC", L"BullTPC", st, (GetSystemMetrics(SM_CXSCREEN) - ww) / 2, (GetSystemMetrics(SM_CYSCREEN) - wh) / 2, ww, wh, nullptr, nullptr, hi, nullptr);
    ShowWindow(w, show); MSG msg; while (GetMessageW(&msg, nullptr, 0, 0)) { TranslateMessage(&msg); DispatchMessageW(&msg); }
    return 0;
}
