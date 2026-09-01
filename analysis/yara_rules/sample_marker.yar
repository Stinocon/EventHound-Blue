/*
 * Regola YARA di esempio/test — sicura e sintetica (nessun campione malevolo reale).
 * Cerca un marker innocuo usato dai test; mostra come propagare una tecnica ATT&CK dai meta.
 * Aggiungere qui (o in un'altra .yar in questa cartella) le regole operative curate.
 */
rule analisi_test_marker
{
    meta:
        description = "Marker sintetico per il test dell'adapter YARA"
        attack = "T1059"
        author = "analisi"
    strings:
        $m = "YARA_TEST_MATCH_MARKER"
    condition:
        $m
}
