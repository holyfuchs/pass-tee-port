from NFCPassportReader import PassportReader
from multiprocessing import Manager, Queue
from nicegui import ui, run
import requests
import time


ENC_IP = "192.168.1.100"

def compute(queue: Queue):
    wallet = queue.get()
    mrz_key = queue.get()
    reader = PassportReader()
    retries = 0
    while True:
        try:
            dg1data, soddata = reader.readPassport(mrz_key, [])
            response = requests.post(f'http://{ENC_IP}:8080/passport_sign', 
                json={
                    'sod': soddata, 
                    'ed1': dg1data, 
                    'address': wallet
                }
            )
            data = response.json()
            queue.put(data['signature'])
            break
        except Exception as e:
            if e == "No Card":
                retries += 1
                if retries > 3:
                    raise e
                time.sleep(1)
                continue
            raise e

shared_state = {}
# ---------------------------------------------------------------------------- #
#                                  Components                                  #
# ---------------------------------------------------------------------------- #
def Header():
    ui.query('.nicegui-content').classes('p-2 gap-0 w-full h-dvh flex flex-col items-center')

    with ui.element('div').classes("h-14 w-full p-2 flex items-center justify-start"):
        ui.label("🪪 Pass-Tee-Port").classes("text-2xl font-bold")

def Footer():
    with ui.element('div').classes("h-14 w-full p-2 flex items-end justify-center"):
        with ui.element('div').classes("flex gap-2 items-center"):
            ui.element('div').classes("h-2 w-2 bg-green-500 rounded-full")
            ui.label("Connected to TEE with IP:")
            ui.label(ENC_IP).classes("font-bold")

def DateInput(label: str, value: str):
    with ui.input(label, placeholder=value) as date:
        with ui.menu().props('no-parent-event') as menu:
            with ui.date().bind_value(date):
                with ui.row().classes('justify-end'):
                    ui.button('Close', on_click=menu.close).props('flat')
        with date.add_slot('append'):
            ui.icon('edit_calendar').on('click', menu.open).classes('cursor-pointer')
    return date


# ---------------------------------------------------------------------------- #
#                                 Success Page                                 #
# ---------------------------------------------------------------------------- #
@ui.page('/success')
def success_page():
    signature = shared_state.get('signature', None)

    with ui.element('div').classes("w-dvw h-dvh flex flex-col gap-3 items-center justify-center"):
        ui.label("Scanning completed successfully 🎉")
        ui.label("Your passport has been scanned. It is now submitted to the TEE.")
        with ui.element('div').classes("flex gap-2 items-center"):
            ui.label("Signature:")
            ui.label(f"{signature}").classes("font-bold")
        ui.button("Scan another passport").on_click(lambda: ui.navigate.to(main_page))


# ---------------------------------------------------------------------------- #
#                                   Main Page                                  #
# ---------------------------------------------------------------------------- #
@ui.page('/')
def main_page():
    queue = Manager().Queue()

    async def process_passport():
        if not wallet_input.validate(return_result=False):
            return

        wallet_input.visible = False
        mrz_key_input.visible = False
        scan_button.visible = False
        spinner.visible = True
        spinnerText.visible = True

        queue.put(wallet_input.value)
        queue.put(mrz_key_input.value)
        try:
            await run.cpu_bound(compute, queue)
        except run.SubprocessException as e:
            ui.notify(e.original_message, type="negative", position="top-right")
            mrz_key_input.visible = True
            wallet_input.visible = True
            scan_button.visible = True
            spinner.visible = False
            spinnerText.visible = False
            return
        shared_state['signature'] = queue.get()
        ui.navigate.to(success_page)

    Header()

    with ui.element('div').classes("w-full flex-1 flex flex-col gap-3 items-center justify-center"):
        mrz_key_input = ui.input(label='Passport MRZ Key', placeholder='123456789123456789123412', password=True, password_toggle_button=False).classes("w-full max-w-md")
        wallet_input = ui.input(
            label='Wallet Address', placeholder='Enter your wallet address',
            validation={
                'Invalid Ethereum address': lambda value: (
                    value.startswith('0x') and len(value) == 42 and all(c in '0123456789abcdefABCDEF' for c in value[2:])
                )
            }
        ).classes("w-full max-w-md")

        scan_button = ui.button('Scan Passport').classes("w-full max-w-md")
        scan_button.on_click(lambda: process_passport())

        spinner = ui.spinner(size="lg").classes("m-2")
        spinnerText = ui.label("Scanning...").classes("m-2")
        spinner.visible = False
        spinnerText.visible = False

    Footer()

ui.run(title='Pass-Tee-Port', native=True, window_size=(800, 600), fullscreen=False)
