"""Exact nested cleanup/truth role required by the current native Future."""
import re

TRUTH_SOURCES = ('background_optimizer_future_public_cleanup',
                 'background_optimizer_future_public_truth')
TRUTH_PACKER = 'background_optimizer_future_public_truth_packer'
TRUTH_PRODUCT = 'future-cleanup-truth.flat'
TRUTH_BRIDGE = 'tools/hia_background_optimizer_future_public_truth_bridge.S'


def truth_capsule_record(product):
    return dict(protocol='HIABFTPK', roles=['cleanup', 'truth'],
                packer=TRUTH_PACKER, product=product,
                native_pack=True, independent_byte_comparison=True)


def admitted_truth_capsule(receipt):
    capsule = receipt.get('public_cleanup_capsule')
    if capsule is None:
        if receipt.get('value_protocol') == 'HIABVP09':
            raise ValueError('current Future release lacks its native truth continuation')
        return None
    if not isinstance(capsule, dict) or set(capsule) != {
            'protocol', 'roles', 'packer', 'product', 'native_pack',
            'independent_byte_comparison'}:
        raise ValueError('unregistered Future cleanup capsule schema')
    product = capsule['product']
    if (not isinstance(product, dict) or set(product) != {'bytes', 'sha256'}
            or type(product['bytes']) is not int or not 0 < product['bytes'] <= 4194304
            or not isinstance(product['sha256'], str)
            or re.fullmatch('[0-9a-f]{64}', product['sha256']) is None):
        raise ValueError('invalid Future cleanup capsule product pin')
    if (capsule['native_pack'] is not True
            or capsule['independent_byte_comparison'] is not True
            or capsule != truth_capsule_record(product)):
        raise ValueError('Future cleanup capsule layout or native construction differs')
    return capsule
