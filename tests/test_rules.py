from cloud_cost_guard.rules import missing_tags, tags_to_dict

def test_tags_to_dict():
    assert tags_to_dict([{"Key": "Owner", "Value": "platform"}]) == {"Owner": "platform"}

def test_missing_tags():
    assert missing_tags({"Environment": "prod", "Owner": " "},
                        ["Environment", "Owner", "CostCenter"]) == ["CostCenter", "Owner"]
