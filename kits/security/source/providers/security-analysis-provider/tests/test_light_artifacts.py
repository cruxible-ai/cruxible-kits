"""Light-artifact inputs preserve presence, source context and honest coverage counts."""
import json

from cruxible_client.contracts.query.results import QueryResultRow
from security_analysis_provider.common import parse_rows, unindexed_counts
from security_analysis_provider.response import inventory, read_inventory


def test_native_tap_values_keep_absence_conflict_and_zero():
    wire = QueryResultRow.model_validate({
        'bindings': [], 'fields': [
            {'name': 'count', 'state': 'present', 'value': 0},
            {'name': 'missing', 'state': 'absent'},
            {'name': 'disputed', 'state': 'conflict'},
        ]}).model_dump(mode='json')
    row, = parse_rows([wire])
    assert row.value('count') == 0
    assert row.value('missing') is None and row.state('missing') == 'absent'
    assert row.value('disputed') is None and row.state('disputed') == 'conflict'


def test_host_sbom_input_context_is_fallback_and_never_scope_coverage():
    body = {'bomFormat': 'CycloneDX', 'metadata': {}, 'components': [
        {'purl': 'pkg:brew/gh@2.86.0'}, {'purl': 'pkg:golang/github.com/cli/cli/v2@v2.86.0'}]}
    result = inventory(json.dumps(body), [], [], 'laptop', asset='host-a', ecosystems={'golang': 'Go'})
    assert result['mine'] == 1 and result['assets'] == 1 and result['runs'] == 2
    assert result['coverage'] == 'asset' and result['revision'] == ''
    assert result['osv_not_indexed'] == {'brew': 1} and result['osv_unindexed'] == 1
    assert any('OSV will not answer brew 1' in item['rationale'] for item in result['items'])
    body['metadata']['properties'] = [{'name':'cruxible.scope','value':'prod'},
                                     {'name':'cruxible.asset','value':'host-b'}]
    scan = read_inventory(json.dumps(body), scope='laptop', asset='host-a')
    assert scan.scope == 'prod' and list(scan.assets) == ['host-b']


def test_unindexed_count_does_not_conflate_distribution_namespaces():
    assert unindexed_counts(['pkg:deb/debian/php@1','pkg:deb/unknown/php@1',
                             'pkg:generic/mine@2','pkg:brew/gh@2'], {'deb/debian':'Debian'}) == {
        'brew':1, 'deb':1, 'generic':1}
