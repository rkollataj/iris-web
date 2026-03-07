#  IRIS Source Code
#  Copyright (C) 2021 - Airbus CyberSecurity (SAS)
#  ir@cyberactionlab.net
#
#  This program is free software; you can redistribute it and/or
#  modify it under the terms of the GNU Lesser General Public
#  License as published by the Free Software Foundation; either
#  version 3 of the License, or (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#  Lesser General Public License for more details.
#
#  You should have received a copy of the GNU Lesser General Public License
#  along with this program; if not, write to the Free Software Foundation,
#  Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

import json
import logging as log
import os
import pickle
import inspect
import ast
from datetime import datetime, timezone
from flask import Blueprint
from flask import current_app
from flask import redirect
from flask import render_template
from flask import request
from flask import url_for
from flask_wtf import FlaskForm
from sqlalchemy import desc

import app
from app.iris_engine.module_handler.module_handler import call_modules_hook
from app.models import CaseAssets
from app.models import CaseReceivedFile
from app.models import CaseTasks
from app.models import Cases
from app.models import CasesEvent
from app.models import CeleryTaskMeta
from app.models import GlobalTasks
from app.models import Ioc
from app.models import IrisHook
from app.models import IrisModule
from app.models import IrisModuleHook
from app.models import Notes
from app.models.alerts import Alert
from app.models.authorization import CaseAccessLevel
from app.models.authorization import Permissions
from app.util import ac_api_case_requires
from app.util import ac_api_requires
from app.util import ac_case_requires
from app.util import ac_requires
from app.util import response_error
from app.util import response_success
from cortex4py.api import Api
from iris_interface.IrisInterfaceStatus import IIStatus

dim_tasks_blueprint = Blueprint(
    'dim_tasks',
    __name__,
    template_folder='templates'
)

basedir = os.path.abspath(os.path.dirname(app.__file__))


def _parse_celery_kwargs(raw_kwargs):
    if raw_kwargs is None:
        return {}

    if isinstance(raw_kwargs, dict):
        return raw_kwargs

    if isinstance(raw_kwargs, bytes):
        try:
            raw_kwargs = raw_kwargs.decode('utf-8')
        except Exception:
            return {}

    if isinstance(raw_kwargs, str):
        if not raw_kwargs.strip():
            return {}

        try:
            parsed = json.loads(raw_kwargs)
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            pass

        try:
            parsed = ast.literal_eval(raw_kwargs)
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            return {}

    return {}


def _build_task_display_name(kwargs_dict, fallback_name):
    if not isinstance(kwargs_dict, dict):
        return fallback_name

    return kwargs_dict.get('task_label') or f"{kwargs_dict.get('module_name')}::{kwargs_dict.get('hook_name')}"


def _collect_live_dim_tasks(existing_task_ids):
    live_entries = []
    try:
        inspector = app.celery.control.inspect(timeout=1)
        active = inspector.active() or {}
        reserved = inspector.reserved() or {}
        scheduled = inspector.scheduled() or {}
    except Exception:
        return live_entries

    def add_entry(task_payload, state_name):
        if not isinstance(task_payload, dict):
            return

        task_id = task_payload.get('id') or task_payload.get('task_id')
        if not task_id or task_id in existing_task_ids:
            return

        task_name = task_payload.get('name', '')
        if 'task_hook_wrapper' not in task_name and 'pipeline_dispatcher' not in task_name:
            return

        kwargs_dict = _parse_celery_kwargs(task_payload.get('kwargs'))
        display_name = _build_task_display_name(kwargs_dict, task_name)
        case_id = kwargs_dict.get('caseid')
        user = kwargs_dict.get('init_user') or "Shadow Iris"

        live_entries.append({
            'state': state_name,
            'case': f'Case #{case_id}' if case_id else "",
            'module': display_name,
            'task_id': task_id,
            'date_done': datetime.now(timezone.utc),
            'user': user
        })
        existing_task_ids.add(task_id)

    for tasks_by_worker, state_name in (
        (active, 'in_progress'),
        (reserved, 'queued'),
    ):
        for worker_tasks in tasks_by_worker.values():
            for task_payload in worker_tasks or []:
                add_entry(task_payload, state_name)

    for worker_tasks in (scheduled or {}).values():
        for scheduled_entry in worker_tasks or []:
            add_entry(scheduled_entry.get('request', {}), 'scheduled')

    return live_entries


def _normalize_ioc_type_name(type_name):
    if not type_name:
        return ''

    return str(type_name).strip().lower().replace('_', '-')


def _ioc_type_to_cortex_data_types(type_name):
    normalized = _normalize_ioc_type_name(type_name)
    if not normalized:
        return []

    mapping = {
        'ip': ['ip'],
        'ip-src': ['ip'],
        'ip-dst': ['ip'],
        'ipv4': ['ip'],
        'ipv6': ['ip'],
        'domain': ['domain', 'fqdn'],
        'hostname': ['domain', 'fqdn'],
        'fqdn': ['fqdn', 'domain'],
        'url': ['url'],
        'uri': ['url'],
        'mail': ['mail'],
        'email': ['mail'],
        'mail-src': ['mail'],
        'mail-dst': ['mail'],
        'hash': ['hash'],
        'md5': ['hash'],
        'sha1': ['hash'],
        'sha224': ['hash'],
        'sha256': ['hash'],
        'sha384': ['hash'],
        'sha512': ['hash'],
        'filename': ['filename'],
        'file': ['file', 'filename']
    }

    return mapping.get(normalized, [normalized])


def _extract_cortex_analyzers_payload(payload):
    if isinstance(payload, list):
        return payload

    if isinstance(payload, dict):
        for key in ('data', 'list', 'items'):
            if isinstance(payload.get(key), list):
                return payload.get(key)

    # cortex4py can return API wrappers/objects; check common containers.
    for attr in ('data', 'list', 'items'):
        value = getattr(payload, attr, None)
        if isinstance(value, list):
            return value

    return []


def _get_cortex_client(cortex_url, cortex_token, verify_tls):
    init_signature = inspect.signature(Api.__init__)
    init_params = init_signature.parameters

    api_kwargs = {}
    if 'verify_cert' in init_params:
        api_kwargs['verify_cert'] = verify_tls
    elif 'cert' in init_params:
        api_kwargs['cert'] = verify_tls

    try:
        cortex_api = Api(cortex_url.rstrip('/'), cortex_token, **api_kwargs)
    except Exception as init_err:
        return None, f'Unable to initialize cortex4py client: {init_err}'

    try:
        _ = cortex_api.analyzers
    except Exception as analyzers_err:
        return None, f'cortex4py client does not expose analyzers API: {analyzers_err}'

    if cortex_api.analyzers is None:
        return None, 'cortex4py client does not expose analyzers API'

    return cortex_api, None


def _query_cortex_analyzers_by_type(cortex_api, cortex_data_type):
    try:
        payload = cortex_api.analyzers.get_by_type(cortex_data_type)
    except Exception as method_err:
        return [], f'cortex4py get_by_type({cortex_data_type}) failed: {method_err}'

    analyzers = _extract_cortex_analyzers_payload(payload)
    return analyzers, None


def _format_analyzer(analyzer):
    analyzer = _normalize_cortex_analyzer(analyzer)

    analyzer_name = (
        analyzer.get('name')
        or analyzer.get('analyzerName')
        or analyzer.get('analyzer_name')
    )

    analyzer_data_types = _extract_analyzer_data_types(analyzer)

    return {
        'id': analyzer.get('id') or analyzer.get('_id') or analyzer.get('analyzerDefinitionId'),
        'name': analyzer_name,
        'version': analyzer.get('version'),
        'description': analyzer.get('description'),
        'data_type_list': analyzer_data_types
    }


def _normalize_cortex_analyzer(analyzer):
    if isinstance(analyzer, dict):
        return analyzer

    if analyzer is None:
        return {}

    for attr in ('json', 'raw', 'data'):
        value = getattr(analyzer, attr, None)
        if callable(value):
            try:
                resolved = value()
                if isinstance(resolved, dict):
                    return resolved
            except Exception:
                continue
        elif isinstance(value, dict):
            return value

    return getattr(analyzer, '__dict__', {}) or {}


def _extract_analyzer_data_types(analyzer):
    if not isinstance(analyzer, dict):
        return []

    candidates = (
        analyzer.get('dataTypeList'),
        analyzer.get('data_type_list'),
        analyzer.get('dataTypes'),
        analyzer.get('data_types')
    )

    for candidate in candidates:
        if isinstance(candidate, list):
            return [str(data_type).strip().lower() for data_type in candidate if str(data_type).strip()]
        if isinstance(candidate, str) and candidate.strip():
            return [candidate.strip().lower()]

    return []


def _resolve_hook_targets(caseid, data_type, targets):
    logs = []
    obj_targets = []

    for target in targets:
        if isinstance(target, str):
            try:
                target = int(target)
            except ValueError:
                return None, ['Invalid target']
        elif not isinstance(target, int):
            return None, ['Invalid target']

        if data_type == 'ioc':
            obj = Ioc.query.filter(Ioc.ioc_id == target).first()

        elif data_type == "case":
            obj = Cases.query.filter(Cases.case_id == caseid).first()

        elif data_type == "asset":
            obj = CaseAssets.query.filter(
                CaseAssets.asset_id == target,
                CaseAssets.case_id == caseid
            ).first()

        elif data_type == "note":
            obj = Notes.query.filter(
                Notes.note_id == target,
                Notes.note_case_id == caseid
            ).first()

        elif data_type == "event":
            obj = CasesEvent.query.filter(
                CasesEvent.event_id == target,
                CasesEvent.case_id == caseid
            ).first()

        elif data_type == "task":
            obj = CaseTasks.query.filter(
                CaseTasks.id == target,
                CaseTasks.task_case_id == caseid
            ).first()

        elif data_type == "evidence":
            obj = CaseReceivedFile.query.filter(
                CaseReceivedFile.id == target,
                CaseReceivedFile.case_id == caseid
            ).first()

        elif data_type == "global_task":
            obj = GlobalTasks.query.filter(
                GlobalTasks.id == target
            ).first()

        elif data_type == 'alert':
            obj = Alert.query.filter(
                Alert.alert_id == target
            ).first()

        else:
            logs.append(f'Data type {data_type} not supported')
            continue

        if not obj:
            logs.append(f'Object ID {target} not found')
            continue

        obj_targets.append(obj)

    return obj_targets, logs


# CONTENT ------------------------------------------------
@dim_tasks_blueprint.route('/dim/tasks', methods=['GET'])
@ac_requires(Permissions.standard_user)
def dim_index(caseid: int, url_redir):
    if url_redir:
        return redirect(url_for('dim.dim_index', cid=caseid))

    form = FlaskForm()

    return render_template('dim_tasks.html', form=form)


@dim_tasks_blueprint.route('/dim/hooks/options/<hook_type>/list', methods=['GET'])
@ac_api_requires()
def list_dim_hook_options_ioc(hook_type):
    mods_options = (IrisModuleHook.query.with_entities(
        IrisModuleHook.manual_hook_ui_name,
        IrisHook.hook_name,
        IrisModule.module_name
    ).filter(
        IrisHook.hook_name == f"on_manual_trigger_{hook_type}",
        IrisModule.is_active == True
    )
    .join(IrisHook, IrisHook.id == IrisModuleHook.hook_id)
    .join(IrisModule, IrisModule.id == IrisModuleHook.module_id)
    .all())

    data = [options._asdict() for options in mods_options]

    return response_success("", data=data)


@dim_tasks_blueprint.route('/dim/hooks/call', methods=['POST'])
@ac_api_case_requires(CaseAccessLevel.full_access)
def dim_hooks_call(caseid):
    js_data = request.json

    if not js_data:
        return response_error('Invalid data')

    hook_name = js_data.get('hook_name')
    if not hook_name:
        return response_error('Missing hook_name')

    hook_ui_name = js_data.get('hook_ui_name')

    targets = js_data.get('targets')
    if not targets:
        return response_error('Missing targets')

    data_type = js_data.get('type')
    if not data_type:
        return response_error('Missing data type')

    module_name = js_data.get('module_name')
    obj_targets, logs = _resolve_hook_targets(caseid, data_type, targets)
    if obj_targets is None:
        return response_error(logs[0] if logs else 'Invalid target')

    index = len(obj_targets)

    if len(obj_targets) > 0:
        call_modules_hook(hook_name=hook_name, hook_ui_name=hook_ui_name, data=obj_targets,
                          caseid=caseid, module_name=module_name)

    if len(logs) > 0:
        return response_error(f"Errors encountered during processing of data. Queued task with {index} objects",
                              data=logs)

    return response_success(f'Queued task with {index} objects')


@dim_tasks_blueprint.route('/dim/hooks/call-extended', methods=['POST'])
@ac_api_case_requires(CaseAccessLevel.full_access)
def dim_hooks_call_extended(caseid):
    js_data = request.json

    if not js_data:
        return response_error('Invalid data')

    hook_name = js_data.get('hook_name')
    if not hook_name:
        return response_error('Missing hook_name')

    hook_ui_name = js_data.get('hook_ui_name')

    targets = js_data.get('targets')
    if not targets:
        return response_error('Missing targets')

    data_type = js_data.get('type')
    if not data_type:
        return response_error('Missing data type')

    module_name = js_data.get('module_name')
    module_input = js_data.get('module_input')
    if module_input is not None and not isinstance(module_input, dict):
        return response_error('module_input must be a JSON object')
    split_per_ioc_analyzer = False
    analyzers = []
    if module_input is not None:
        split_per_ioc_analyzer = bool(module_input.get('split_per_ioc_analyzer', False))
        analyzers = module_input.get('analyzers', [])
        if analyzers is not None and not isinstance(analyzers, list):
            return response_error('module_input.analyzers must be an array')

    obj_targets, logs = _resolve_hook_targets(caseid, data_type, targets)
    if obj_targets is None:
        return response_error(logs[0] if logs else 'Invalid target')

    index = len(obj_targets)
    queued_tasks = index

    # For Cortex "Run analyzer" payloads, force one DIM task per IOC/analyzer pair
    # even if the UI did not send split_per_ioc_analyzer (e.g. stale browser cache).
    if (module_input is not None
            and isinstance(analyzers, list)
            and len(analyzers) > 0
            and hook_name == 'on_manual_trigger_ioc'
            and str(hook_ui_name or '').strip().lower() in ('run analyzer', 'run analyzers')):
        split_per_ioc_analyzer = True

    if len(obj_targets) > 0:
        if split_per_ioc_analyzer:
            cleaned_analyzers = []
            seen = set()
            for analyzer in analyzers or []:
                analyzer_name = str(analyzer).strip()
                if not analyzer_name or analyzer_name in seen:
                    continue
                seen.add(analyzer_name)
                cleaned_analyzers.append(analyzer_name)

            if len(cleaned_analyzers) == 0:
                return response_error('module_input.analyzers is required when split_per_ioc_analyzer is true')

            queued_tasks = 0
            for target in obj_targets:
                for analyzer_name in cleaned_analyzers:
                    hook_data = {
                        'targets': [target],
                        'module_input': {
                            'analyzers': [analyzer_name]
                        }
                    }
                    call_modules_hook(
                        hook_name=hook_name,
                        hook_ui_name=hook_ui_name,
                        data=hook_data,
                        caseid=caseid,
                        module_name=module_name,
                        task_label=(
                            f'Cortex analyzer: '
                            f'{str(getattr(target, "ioc_value", "unknown"))[:96]}'
                            f' :: {analyzer_name}'
                        )
                    )
                    queued_tasks += 1
        else:
            hook_data = obj_targets
            if module_input is not None:
                hook_data = {
                    'targets': obj_targets,
                    'module_input': module_input
                }

            call_modules_hook(
                hook_name=hook_name,
                hook_ui_name=hook_ui_name,
                data=hook_data,
                caseid=caseid,
                module_name=module_name
            )

    if len(logs) > 0:
        return response_error(f"Errors encountered during processing of data. Queued {queued_tasks} task(s)",
                              data=logs)

    return response_success(f'Queued {queued_tasks} task(s)')


@dim_tasks_blueprint.route('/dim/hooks/cortex/analyzers', methods=['POST'])
@ac_api_case_requires(CaseAccessLevel.full_access)
def dim_hooks_list_cortex_analyzers(caseid):
    js_data = request.json
    if not js_data:
        return response_error('Invalid data')

    targets = js_data.get('targets')
    if not targets:
        return response_error('Missing targets')

    data_type = js_data.get('type', 'ioc')
    if data_type != 'ioc':
        return response_error('Only ioc type is supported')

    obj_targets, logs = _resolve_hook_targets(caseid, data_type, targets)
    if obj_targets is None:
        return response_error(logs[0] if logs else 'Invalid target')

    log.info(
        f'Cortex analyzers request received: case={caseid}, targets={len(targets)}, resolved={len(obj_targets)}'
    )

    cortex_url = current_app.config.get('CORTEX_URL')
    cortex_token = current_app.config.get('CORTEX_TOKEN')
    if not cortex_url or not cortex_token:
        log.warning('Cortex analyzers request rejected: CORTEX_URL or CORTEX_TOKEN is missing')
        return response_error('Cortex is not configured. Set CORTEX_URL and CORTEX_TOKEN', status=503)

    verify_tls = current_app.config.get('TLS_ROOT_CA')
    cortex_api, cortex_error = _get_cortex_client(cortex_url, cortex_token, verify_tls)
    if cortex_error:
        log.warning(f'Cortex analyzers lookup failed: {cortex_error}')
        return response_error(cortex_error, status=502)

    expected_type_set = set()
    for ioc in obj_targets:
        expected_type_set.update(
            _ioc_type_to_cortex_data_types(ioc.ioc_type.type_name if ioc.ioc_type else None)
        )

    analyzers_by_cortex_type = {}
    for cortex_type in sorted(expected_type_set):
        type_analyzers, type_error = _query_cortex_analyzers_by_type(cortex_api, cortex_type)
        if type_error:
            log.warning(f'Cortex analyzers lookup failed: {type_error}')
            return response_error(type_error, status=502)

        analyzers_by_cortex_type[cortex_type] = type_analyzers
        log.info(
            f'Cortex analyzers received via get_by_type for type={cortex_type}: count={len(type_analyzers)}'
        )

    observables = []
    unique_analyzers = {}

    for ioc in obj_targets:
        expected_data_types = _ioc_type_to_cortex_data_types(
            ioc.ioc_type.type_name if ioc.ioc_type else None
        )

        matched = []
        if expected_data_types:
            type_matches = []
            for expected_type in expected_data_types:
                type_matches.extend(analyzers_by_cortex_type.get(expected_type, []))

            dedup = {}
            for analyzer in type_matches:
                formatted = _format_analyzer(analyzer)
                analyzer_key = formatted.get('id') or formatted.get('name')
                if analyzer_key:
                    dedup[analyzer_key] = formatted

            matched = list(dedup.values())

        for analyzer in matched:
            analyzer_id = analyzer.get('id') or analyzer.get('name')
            if analyzer_id:
                unique_analyzers[analyzer_id] = analyzer

        observables.append({
            'ioc_id': ioc.ioc_id,
            'ioc_value': ioc.ioc_value,
            'ioc_type': ioc.ioc_type.type_name if ioc.ioc_type else None,
            'expected_cortex_data_types': expected_data_types,
            'analyzers': matched
        })

    response_data = {
        'observables': observables,
        'analyzers_union': list(unique_analyzers.values()),
        'errors': logs
    }

    log.info(
        'Cortex analyzers response built: '
        f'case={caseid}, observables={len(observables)}, union={len(response_data["analyzers_union"])}, '
        f'resolve_errors={len(logs)}'
    )

    return response_success('Fetched Cortex analyzers', data=response_data)


@dim_tasks_blueprint.route('/dim/tasks/list/<int:count>', methods=['GET'])
@ac_api_requires()
def list_dim_tasks(count):
    tasks = CeleryTaskMeta.query.filter(
        ~ CeleryTaskMeta.name.like('app.iris_engine.updater.updater.%')
    ).order_by(desc(CeleryTaskMeta.date_done)).limit(count).all()

    data = []

    for row in tasks:

        tkp = {}
        tkp['state'] = row.status
        tkp['case'] = "Unknown"
        tkp['module'] = row.name
        tkp['task_id'] = row.task_id
        tkp['date_done'] = row.date_done
        tkp['user'] = "Unknown"

        try:
            tinfo = row.result
        except AttributeError:
            # Legacy task
            data.append(tkp)
            continue

        if row.name is not None and 'task_hook_wrapper' in row.name:
            task_name = f"{row.kwargs}::{row.kwargs}"
        else:
            task_name = row.name

        user = None
        case_name = None
        if row.kwargs and row.kwargs != b'{}':
            kwargs = _parse_celery_kwargs(row.kwargs)
            if kwargs:
                user = kwargs.get('init_user')
                case_name = f"Case #{kwargs.get('caseid')}"
                task_name = _build_task_display_name(kwargs, task_name)

        try:
            result = pickle.loads(row.result)
        except:
            result = None

        if isinstance(result, IIStatus):
            try:
                success = result.is_success()
            except:
                success = None
        else:
            success = None

        tkp['state'] = "success" if success else str(row.result)
        tkp['user'] = user if user else "Shadow Iris"
        tkp['module'] = task_name
        tkp['case'] = case_name if case_name else ""

        data.append(tkp)

    existing_task_ids = {row.get('task_id') for row in data if row.get('task_id')}
    data.extend(_collect_live_dim_tasks(existing_task_ids))
    data.sort(key=lambda row: row.get('date_done') or datetime.min.replace(tzinfo=timezone.utc), reverse=True)

    return response_success("", data=data)


@dim_tasks_blueprint.route('/dim/tasks/status/<task_id>', methods=['GET'])
@ac_case_requires(CaseAccessLevel.read_only, CaseAccessLevel.full_access)
def task_status(task_id, caseid, url_redir):
    if url_redir:
        return response_error("Invalid request")

    task = app.celery.AsyncResult(task_id)

    try:
        tinfo = task.info
    except AttributeError:
        # Legacy task
        task_info = {}
        task_info['Danger'] = 'This task was executed in a previous version of IRIS and the status cannot be read ' \
                              'anymore.'
        task_info['Note'] = 'All the data readable by the current IRIS version is displayed in ' \
                            'the table.'
        task_info['Additional information'] = 'The results of this tasks were stored in a pickled Class which does' \
                                              ' not exists anymore in current IRIS version.'
        return render_template("modal_task_info.html", data=task_info, task_id=task.id)

    task_info = {}
    task_info['Task ID'] = task_id
    task_info['Task finished on'] = task.date_done
    task_info['Task state']: task.state.lower()
    task_info['Engine']: task.name if task.name else "No engine. Unrecoverable shadow failure"

    task_meta = task._get_task_meta()

    if task_meta.get('name') \
            and ('task_hook_wrapper' in task_meta.get('name') or 'pipeline_dispatcher' in task_meta.get('name')):
        task_info['Module name'] = task_meta.get('kwargs').get('module_name')
        task_info['Hook name'] = task_meta.get('kwargs').get('hook_name')
        task_info['Task label'] = task_meta.get('kwargs').get('task_label')
        task_info['User'] = task_meta.get('kwargs').get('init_user')
        task_info['Case ID'] = task_meta.get('kwargs').get('caseid')

    if isinstance(task.info, IIStatus):
        success = task.info.is_success()
        task_info['Logs'] = task.info.get_logs()

    else:
        success = None
        task_info['User'] = "Shadow Iris"
        task_info['Logs'] = ['Task did not returned a valid IIStatus object']

    if task_meta.get('traceback'):
        task_info['Traceback'] = task.traceback

    task_info['Success'] = "Success" if success else "Failure"

    return render_template("modal_task_info.html", data=task_info, task_id=task.id)
